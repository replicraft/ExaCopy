//! Deterministic plans for single-file copies in owner-managed local APFS directories.

use std::num::NonZeroU32;

use exacopy_endpoint::{MAX_FILE_LENGTH, UnixComponent};
use exacopy_journal::{
	DarwinFileIdentity, JournalContext, JournalEntryId, JournalEpoch, JournalJobId,
	ObservedTimestamp, OwnerProfileId, RootCapabilityId,
};

mod error;
mod wire;

pub use error::DarwinCopyPlanError;
pub use wire::MAX_DARWIN_COPY_PLAN_BYTES;

#[cfg(test)]
mod tests;

// Darwin sys/syslimits.h defines both UID_MAX and GID_MAX as 2147483647U.
const DARWIN_UID_MAX: u32 = 2_147_483_647;
const DARWIN_GID_MAX: u32 = 2_147_483_647;
const OWNER_PRIVATE_MODE: u16 = 0o600;

/// The selected job, entry, run epoch, and owner profile for one copy attempt.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PlanAttempt {
	/// The coordinator-assigned job UUIDv7.
	pub job: JournalJobId,
	/// The run epoch within the job.
	pub epoch: JournalEpoch,
	/// The coordinator-assigned entry identity.
	pub entry: JournalEntryId,
	/// The submitting owner's independently selected local profile.
	pub profile: OwnerProfileId,
}

/// The original basic metadata of the admitted regular source.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SourceMetadata {
	uid: NonZeroU32,
	gid: u32,
	accessed_at: ObservedTimestamp,
	modified_at: ObservedTimestamp,
	changed_at: ObservedTimestamp,
}

impl SourceMetadata {
	/// Records source ownership, permission bits, and timestamps at admission.
	/// The caller captures access time before reading file content. Change time
	/// supports source revalidation. The destination preserves access and
	/// modification times and must already have matching ownership.
	///
	/// # Errors
	/// Refuses root ownership, IDs beyond Darwin's bounds, and permission
	/// modes outside the fixed owner-private `0600` policy.
	pub fn new(
		mode: u16,
		uid: u32,
		gid: u32,
		accessed_at: ObservedTimestamp,
		modified_at: ObservedTimestamp,
		changed_at: ObservedTimestamp,
	) -> Result<Self, DarwinCopyPlanError> {
		if mode != OWNER_PRIVATE_MODE || uid > DARWIN_UID_MAX || gid > DARWIN_GID_MAX {
			return Err(DarwinCopyPlanError::UnsupportedMetadata);
		}
		let uid = NonZeroU32::new(uid).ok_or(DarwinCopyPlanError::UnsupportedMetadata)?;
		Ok(Self {
			uid,
			gid,
			accessed_at,
			modified_at,
			changed_at,
		})
	}

	/// Returns the ordinary permission bits required at publication.
	#[must_use]
	pub const fn mode(self) -> u16 {
		OWNER_PRIVATE_MODE
	}

	/// Returns the nonroot owner identifier.
	#[must_use]
	pub const fn uid(self) -> NonZeroU32 {
		self.uid
	}

	/// Returns the observed owning group identifier, which can be zero.
	#[must_use]
	pub const fn gid(self) -> u32 {
		self.gid
	}

	/// Returns access time captured before content reads.
	#[must_use]
	pub const fn accessed_at(self) -> ObservedTimestamp {
		self.accessed_at
	}

	/// Returns the original source modification time.
	#[must_use]
	pub const fn modified_at(self) -> ObservedTimestamp {
		self.modified_at
	}

	/// Returns the original source inode change time.
	#[must_use]
	pub const fn changed_at(self) -> ObservedTimestamp {
		self.changed_at
	}
}

/// The held source root and the observation of its selected regular file.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SourcePlanBinding<'name> {
	/// The caller's source-root capability identifier.
	pub root_id: RootCapabilityId,
	/// The native identity obtained through the held source root.
	pub root_identity: DarwinFileIdentity,
	/// The native identity obtained through the held read-only source file.
	pub file_identity: DarwinFileIdentity,
	/// The planned logical unnamed stream length.
	pub length: u64,
	/// The basic source metadata captured at admission.
	pub metadata: SourceMetadata,
	/// The source file's raw component beneath the source root.
	pub component: UnixComponent<'name>,
}

/// The held destination root and the selected absent target beneath it.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DestinationPlanBinding<'name> {
	/// The caller's destination-root capability identifier.
	pub root_id: RootCapabilityId,
	/// The native identity obtained through the held destination root.
	pub root_identity: DarwinFileIdentity,
	/// The raw component selected for exclusive publication.
	pub component: UnixComponent<'name>,
}

/// A private plan for independent BLAKE3 read-back and exclusive Darwin publication.
///
/// The fixed policy selects an absent target, a single-link ordinary source,
/// and strict basic metadata: owner-private mode, matching ownership, original
/// access and modification times, empty effective ACL, no BSD flags, no visible
/// extended attribute names, and no resource fork. Change and birth times are
/// source observations. File reads may advance access time. The private job
/// name derives from the job UUID. The signed owner format fixes its layout.
/// The journal binds the actual private stage name. The plan carries
/// prior observations only. The executor supplies independently authorized
/// roots and checks current observations and every publication prerequisite.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DarwinCopyPlan<'name> {
	attempt: PlanAttempt,
	source: SourcePlanBinding<'name>,
	destination: DestinationPlanBinding<'name>,
}

impl<'name> DarwinCopyPlan<'name> {
	/// Binds an attempt and two independently held roots to the fixed copy policy.
	///
	/// # Errors
	/// Refuses excessive extent, a source outside its root volume, conflicting
	/// native identities, and identical source and target names in one directory.
	/// The caller must still check live filesystem name equivalence and absence.
	pub fn new(
		attempt: PlanAttempt,
		source: SourcePlanBinding<'name>,
		destination: DestinationPlanBinding<'name>,
	) -> Result<Self, DarwinCopyPlanError> {
		if source.length > MAX_FILE_LENGTH {
			return Err(DarwinCopyPlanError::SourceTooLong);
		}
		if source.root_identity.volume() != source.file_identity.volume() {
			return Err(DarwinCopyPlanError::SourceOutsideRootVolume);
		}
		let same_root = source.root_identity == destination.root_identity;
		if (!same_root
			&& (source.root_id == destination.root_id
				|| possibly_same_object(source.root_identity, destination.root_identity)))
			|| possibly_same_object(source.file_identity, destination.root_identity)
			|| possibly_same_object(source.root_identity, source.file_identity)
		{
			return Err(DarwinCopyPlanError::ConflictingIdentities);
		}
		if same_root && source.component == destination.component {
			return Err(DarwinCopyPlanError::ConflictingNames);
		}
		Ok(Self {
			attempt,
			source,
			destination,
		})
	}

	/// Returns the planned job, epoch, entry and profile identifiers.
	#[must_use]
	pub const fn attempt(&self) -> PlanAttempt {
		self.attempt
	}

	/// Returns the source grant and observations.
	#[must_use]
	pub const fn source(&self) -> SourcePlanBinding<'name> {
		self.source
	}

	/// Returns the destination grant, root observation, and selected target.
	#[must_use]
	pub const fn destination(&self) -> DestinationPlanBinding<'name> {
		self.destination
	}

	/// Returns the journal context bound to the canonical plan digest.
	#[must_use]
	pub fn context(&self) -> JournalContext {
		JournalContext {
			job: self.attempt.job,
			epoch: self.attempt.epoch,
			plan_digest: self.digest(),
		}
	}
}

fn possibly_same_object(left: DarwinFileIdentity, right: DarwinFileIdentity) -> bool {
	// Conflicting supporting observations on the same inode do not resolve aliasing.
	left.inode() == right.inode()
		&& (left.volume().device() == right.volume().device()
			|| left.volume().physical_fsid() == right.volume().physical_fsid())
}
