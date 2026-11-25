use core::fmt;
use core::num::NonZeroU32;

use exacopy_endpoint::{MAX_FILE_LENGTH, UnixComponent};
use exacopy_model::StageId;

use super::DarwinPreparedError;
use crate::{DarwinFileIdentity, OwnerTimestamp, PreparedError, RootCapabilityId};

const MANAGED_SOURCE_MODE: u32 = 0o600;
// Darwin's sys/syslimits.h defines UID_MAX as 2147483647U.
const DARWIN_UID_MAX: u32 = 2_147_483_647;

/// A root capability and the native directory identity observed through it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinRootBinding {
	/// The identifier of the caller-provisioned root capability.
	pub id: RootCapabilityId,
	/// The native directory observation associated with the root capability.
	pub identity: DarwinFileIdentity,
}

/// The pre-read source access, modification, and inode change timestamps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinSourceTimes {
	/// Access time captured before any source data reads.
	pub accessed_at: OwnerTimestamp,
	/// Content modification time.
	pub modified_at: OwnerTimestamp,
	/// Inode change time used for revalidation.
	pub changed_at: OwnerTimestamp,
}

/// A source metadata observation in the strict managed APFS basic fidelity profile.
///
/// The coordinator attests to a regular single-link file with no visible xattrs,
/// no resource fork, an empty effective ACL, and no BSD flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinSourceMetadata {
	owner: NonZeroU32,
	group: u32,
}

impl DarwinSourceMetadata {
	/// Records the supported mode, owner and group after the strict checks.
	///
	/// # Errors
	/// Refuses observations outside the profile's admitted mode or UID.
	pub fn new(mode: u32, owner: NonZeroU32, group: u32) -> Result<Self, PreparedError> {
		if mode != MANAGED_SOURCE_MODE || owner.get() > DARWIN_UID_MAX {
			return Err(PreparedError::UnsupportedSourceMetadata);
		}
		Ok(Self { owner, group })
	}

	/// Returns the captured source permissions.
	#[must_use]
	pub const fn mode(self) -> u32 {
		MANAGED_SOURCE_MODE
	}

	/// Returns the captured source UID.
	#[must_use]
	pub const fn owner(self) -> NonZeroU32 {
		self.owner
	}

	/// Returns the captured source GID.
	#[must_use]
	pub const fn group(self) -> u32 {
		self.group
	}
}

/// The live regular-file observation recorded before copying its unnamed stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinSourceView<'a> {
	root: DarwinRootBinding,
	component: UnixComponent<'a>,
	identity: DarwinFileIdentity,
	length: u64,
	times: DarwinSourceTimes,
	metadata: DarwinSourceMetadata,
}

impl<'a> DarwinSourceView<'a> {
	/// Binds the native file, pre-read times, and admitted metadata to the source root.
	///
	/// # Errors
	/// Refuses excessive extent, a root/file volume mismatch, or a native root/file alias.
	pub fn new(
		root: DarwinRootBinding,
		component: UnixComponent<'a>,
		identity: DarwinFileIdentity,
		length: u64,
		times: DarwinSourceTimes,
		metadata: DarwinSourceMetadata,
	) -> Result<Self, DarwinPreparedError> {
		if length > MAX_FILE_LENGTH {
			return Err(PreparedError::InvalidSourceLength.into());
		}
		if root.identity.volume() != identity.volume() {
			return Err(DarwinPreparedError::VolumeMismatch);
		}
		if same_native_object(root.identity, identity) {
			return Err(DarwinPreparedError::IdentityAlias);
		}
		Ok(Self {
			root,
			component,
			identity,
			length,
			times,
			metadata,
		})
	}

	/// Returns the held root capability and capture of its directory identity.
	#[must_use]
	pub const fn root(self) -> DarwinRootBinding {
		self.root
	}

	/// Returns the raw name relative to that root.
	#[must_use]
	pub const fn component(self) -> UnixComponent<'a> {
		self.component
	}

	/// Returns the native observation of the opened source file.
	#[must_use]
	pub const fn identity(self) -> DarwinFileIdentity {
		self.identity
	}

	/// Returns the pre-read logical extent of the unnamed stream.
	#[must_use]
	pub const fn length(self) -> u64 {
		self.length
	}

	/// Returns the three timestamps used for metadata and re-observation.
	#[must_use]
	pub const fn times(self) -> DarwinSourceTimes {
		self.times
	}

	/// Returns the source metadata admitted under the strict profile.
	#[must_use]
	pub const fn metadata(self) -> DarwinSourceMetadata {
		self.metadata
	}
}

/// The exact opaque model stage token allocated by the Darwin stage adapter.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct DarwinStageId([u8; 16]);

impl DarwinStageId {
	/// Wraps the exact bytes obtained from the stage adapter or bounded decoding.
	#[must_use]
	pub const fn from_bytes(bytes: [u8; 16]) -> Self {
		Self(bytes)
	}

	/// Returns the persisted token bytes in adapter order.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 16] {
		&self.0
	}

	/// Returns the corresponding model identity.
	#[must_use]
	pub const fn model_id(self) -> StageId {
		StageId::from_bytes(self.0)
	}
}

impl fmt::Debug for DarwinStageId {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("DarwinStageId(<redacted>)")
	}
}

/// The initial observation of an exclusively created empty regular stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinStageObservation<'a> {
	/// The exact logical model binding token allocated for this stage.
	pub id: DarwinStageId,
	/// The initial native identity observed through the held private stage directory.
	pub directory: DarwinFileIdentity,
	/// The native identity of the empty stage file observed at creation.
	pub identity: DarwinFileIdentity,
	/// The raw private component relative to the held stage directory.
	pub component: UnixComponent<'a>,
}

// Mutable birth time and an unavailable generation cannot disprove an alias.
pub(crate) fn same_native_object(left: DarwinFileIdentity, right: DarwinFileIdentity) -> bool {
	left.volume() == right.volume() && left.inode() == right.inode()
}
