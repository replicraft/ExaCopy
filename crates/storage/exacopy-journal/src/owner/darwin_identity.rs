use std::num::{NonZeroI32, NonZeroU32, NonZeroU64};

use super::{OwnerError, OwnerTimestamp};

// Darwin's sys/param.h defines NODEV as (dev_t)(-1).
const DARWIN_NODEV: i32 = -1;

/// A Darwin managed APFS volume observation under the held adapter capability.
///
/// The physical FSID contains the two native words of `ATTR_CMN_FSID` with
/// `FSOPT_RETURN_REALDEV`. A volume observation cannot authenticate a remount
/// or replacement volume. The adapter must independently establish provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinVolumeIdentity {
	device: NonZeroI32,
	physical_fsid: [u32; 2],
}

impl DarwinVolumeIdentity {
	/// Wraps the signed Darwin `dev_t` and ordered physical FSID words.
	///
	/// # Errors
	/// Returns [`OwnerError::UnsupportedIdentity`] for device zero, Darwin
	/// `NODEV`, or an all-zero FSID.
	pub fn new(device: i32, physical_fsid: [u32; 2]) -> Result<Self, OwnerError> {
		let device = NonZeroI32::new(device).ok_or(OwnerError::UnsupportedIdentity)?;
		if device.get() == DARWIN_NODEV || physical_fsid == [0; 2] {
			return Err(OwnerError::UnsupportedIdentity);
		}
		Ok(Self {
			device,
			physical_fsid,
		})
	}

	/// Returns the signed native Darwin device number without widening it.
	#[must_use]
	pub const fn device(self) -> i32 {
		self.device.get()
	}

	/// Returns the first and second words of the native physical FSID, in order.
	#[must_use]
	pub const fn physical_fsid(self) -> [u32; 2] {
		self.physical_fsid
	}
}

/// A Darwin managed APFS inode observation under the held adapter capability.
///
/// The birth timestamp is supporting evidence. It is mutable and cannot
/// establish permanent protection from inode reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DarwinFileIdentity {
	volume: DarwinVolumeIdentity,
	inode: NonZeroU64,
	generation: Option<NonZeroU32>,
	birth: OwnerTimestamp,
}

impl DarwinFileIdentity {
	/// Wraps native inode, generation, and birth observations. Use
	/// `NonZeroU32::new(st_gen)` to map native zero to unavailable generation.
	#[must_use]
	pub const fn new(
		volume: DarwinVolumeIdentity,
		inode: NonZeroU64,
		generation: Option<NonZeroU32>,
		birth: OwnerTimestamp,
	) -> Self {
		Self {
			volume,
			inode,
			generation,
			birth,
		}
	}

	/// Returns the observed native volume separately from the inode.
	#[must_use]
	pub const fn volume(self) -> DarwinVolumeIdentity {
		self.volume
	}

	/// Returns the native inode number.
	#[must_use]
	pub const fn inode(self) -> NonZeroU64 {
		self.inode
	}

	/// Returns the available nonzero native inode generation.
	#[must_use]
	pub const fn generation(self) -> Option<NonZeroU32> {
		self.generation
	}

	/// Returns the supporting birth timestamp observation.
	#[must_use]
	pub const fn birth(self) -> OwnerTimestamp {
		self.birth
	}

	/// Checks whether two observations could identify the same native inode.
	///
	/// When either volume identifier agrees, conflicting volume, generation, or
	/// birth observations cannot safely establish that equal inodes are distinct.
	#[must_use]
	pub fn may_alias(self, other: Self) -> bool {
		self.inode == other.inode
			&& (self.volume.device == other.volume.device
				|| self.volume.physical_fsid == other.volume.physical_fsid)
	}
}
