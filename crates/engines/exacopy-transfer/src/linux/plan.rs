//! The private Linux one-file copy plan and its deterministic data representation.

use std::error::Error;
use std::fmt;

use exacopy_endpoint::{MAX_FILE_LENGTH, NameError, UnixComponent};
use exacopy_journal::{
	DestinationRootBinding, JournalContext, JournalEntryId, JournalEpoch, JournalJobId,
	LinuxFileIdentity, ObservedTimestamp, RootCapabilityId,
};

mod wire;

pub use wire::MAX_LOCAL_COPY_PLAN_BYTES;

#[cfg(test)]
mod tests;

/// The selected identities and private names for one run's single entry.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PlanAttempt<'name> {
	/// The coordinator-assigned job UUIDv7.
	pub job: JournalJobId,
	/// The run generation within this job.
	pub epoch: JournalEpoch,
	/// The selected entry UUID.
	pub entry: JournalEntryId,
	/// The job directory component beneath the held destination root.
	pub job_name: UnixComponent<'name>,
	/// The staged file component beneath the job's owned stage directory.
	pub stage_name: UnixComponent<'name>,
}

/// The observed file and the root from which the coordinator admitted it.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SourcePlanBinding<'name> {
	/// The caller's source-root authorization identifier.
	pub root_id: RootCapabilityId,
	/// The device and inode observed through the held source directory.
	pub root_identity: LinuxFileIdentity,
	/// The device and inode observed through the held read-only source file.
	pub file_identity: LinuxFileIdentity,
	/// The planned logical stream length.
	pub length: u64,
	/// Best-effort source modification time from the planning observation.
	pub modified_at: ObservedTimestamp,
	/// Best-effort source inode change time from the planning observation.
	pub changed_at: ObservedTimestamp,
	/// The source file's raw component beneath the held source root.
	pub component: UnixComponent<'name>,
}

/// The observed destination directory and the selected new name.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DestinationPlanBinding<'name> {
	/// The caller's destination-root identifier and its observed device and inode.
	pub root: DestinationRootBinding,
	/// The intended new file component beneath the held destination root.
	pub component: UnixComponent<'name>,
}

/// The private v1 plan for a local Linux regular-file copy into one new name.
///
/// Its fixed policy is independent BLAKE3 read-back, the Linux baseline metadata
/// subset, and exclusive no-replace publication. Identities are past observations.
/// A plan and its digest carry no authority. A consumer needs independently
/// authorized roots and must match current handles and enforce all effect gates.
/// This local persistence format has no public Plan v1 envelope or pages.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LocalCopyPlan<'name> {
	attempt: PlanAttempt<'name>,
	source: SourcePlanBinding<'name>,
	destination: DestinationPlanBinding<'name>,
}

impl<'name> LocalCopyPlan<'name> {
	/// Binds one admitted source, destination, and attempt to the fixed local policy.
	///
	/// # Errors
	/// Returns an error for excessive length, contradictory observations, or
	/// literally overlapping source, private job, and intended destination names.
	pub fn new(
		attempt: PlanAttempt<'name>,
		source: SourcePlanBinding<'name>,
		destination: DestinationPlanBinding<'name>,
	) -> Result<Self, LocalCopyPlanError> {
		if source.length > MAX_FILE_LENGTH {
			return Err(LocalCopyPlanError::SourceTooLong);
		}
		if source.file_identity == source.root_identity
			|| source.file_identity == destination.root.identity
			|| (source.root_id == destination.root.id
				&& source.root_identity != destination.root.identity)
		{
			return Err(LocalCopyPlanError::ConflictingIdentities);
		}
		if attempt.job_name == destination.component
			|| (source.root_identity == destination.root.identity
				&& (source.component == destination.component
					|| source.component == attempt.job_name))
		{
			return Err(LocalCopyPlanError::ConflictingNames);
		}
		Ok(Self {
			attempt,
			source,
			destination,
		})
	}

	/// Returns the planned attempt identities and private names.
	#[must_use]
	pub const fn attempt(&self) -> PlanAttempt<'name> {
		self.attempt
	}

	/// Returns the planned source binding and observation.
	#[must_use]
	pub const fn source(&self) -> SourcePlanBinding<'name> {
		self.source
	}

	/// Returns the planned destination binding and component.
	#[must_use]
	pub const fn destination(&self) -> DestinationPlanBinding<'name> {
		self.destination
	}

	/// Returns the journal context derived from the exact plan.
	#[must_use]
	pub fn context(&self) -> JournalContext {
		JournalContext {
			job: self.attempt.job,
			epoch: self.attempt.epoch,
			plan_digest: self.digest(),
		}
	}
}

/// A plan outside the supported bounded local representation.
#[derive(Debug)]
#[non_exhaustive]
pub enum LocalCopyPlanError {
	/// The complete serialized input exceeds the v1 wire bound.
	PayloadTooLarge,
	/// A CBOR value has the wrong type, is malformed, or is truncated.
	InvalidCbor(minicbor::decode::Error),
	/// The input does not have the required definite, fixed-length arrays.
	InvalidShape,
	/// The format version is unsupported.
	UnsupportedVersion,
	/// The operation, action, or required policy is unsupported.
	UnsupportedPolicy,
	/// The encoded job identifier fails the UUIDv7 contract.
	InvalidJobId,
	/// An encoded root identifier fails the capability UUID contract.
	InvalidRootId,
	/// The encoded entry identifier is not an exact UUID-length byte string.
	InvalidEntryId,
	/// A raw Unix component fails the shared endpoint name contract.
	InvalidComponent(NameError),
	/// A source timestamp has an invalid fractional second.
	InvalidSourceTimestamp,
	/// The planned logical length exceeds the local adapter limit.
	SourceTooLong,
	/// The observations assign contradictory identities to a root or file.
	ConflictingIdentities,
	/// The planned names literally overlap within a bound directory.
	ConflictingNames,
	/// The encoding is noncanonical or contains trailing bytes.
	NonCanonical,
}

impl fmt::Display for LocalCopyPlanError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::PayloadTooLarge => formatter.write_str("local copy plan exceeds the byte limit"),
			Self::InvalidCbor(error) => write!(formatter, "invalid local copy plan CBOR ({error})"),
			Self::InvalidShape => formatter.write_str("invalid local copy plan shape"),
			Self::UnsupportedVersion => formatter.write_str("unsupported local copy plan version"),
			Self::UnsupportedPolicy => formatter.write_str("unsupported local copy plan policy"),
			Self::InvalidJobId => formatter.write_str("invalid job identity in local copy plan"),
			Self::InvalidRootId => formatter.write_str("invalid root identity in local copy plan"),
			Self::InvalidEntryId => {
				formatter.write_str("invalid entry identity in local copy plan")
			}
			Self::InvalidComponent(error) => write!(formatter, "invalid plan component ({error})"),
			Self::InvalidSourceTimestamp => {
				formatter.write_str("invalid source timestamp in local plan")
			}
			Self::SourceTooLong => {
				formatter.write_str("planned file exceeds the local length limit")
			}
			Self::ConflictingIdentities => formatter.write_str("conflicting local plan identities"),
			Self::ConflictingNames => formatter.write_str("conflicting local plan names"),
			Self::NonCanonical => formatter.write_str("local copy plan encoding is not canonical"),
		}
	}
}

impl Error for LocalCopyPlanError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::InvalidCbor(error) => Some(error),
			Self::InvalidComponent(error) => Some(error),
			_ => None,
		}
	}
}

impl From<minicbor::decode::Error> for LocalCopyPlanError {
	fn from(error: minicbor::decode::Error) -> Self {
		Self::InvalidCbor(error)
	}
}
