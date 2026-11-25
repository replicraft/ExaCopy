use std::num::{NonZeroU32, NonZeroU64};

use rustix::fs::Stat;

use super::PhysicalFsid;

/// A normalized timestamp taken from a held Darwin object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedTimestamp {
	seconds: i64,
	nanoseconds: u32,
}

impl ManagedTimestamp {
	pub(super) fn from_stat_parts(seconds: i64, nanoseconds: i64) -> Option<Self> {
		let nanoseconds = u32::try_from(nanoseconds).ok()?;
		(nanoseconds < 1_000_000_000).then_some(Self {
			seconds,
			nanoseconds,
		})
	}

	/// Returns the whole seconds relative to the Unix epoch.
	#[must_use]
	pub const fn seconds(self) -> i64 {
		self.seconds
	}

	/// Returns the normalized fractional nanoseconds.
	#[must_use]
	pub const fn nanoseconds(self) -> u32 {
		self.nanoseconds
	}
}

/// Native observation of one object held under a managed APFS capability.
/// Device and physical FSID describe the current mount. Birth time supports
/// identity checks when generation is unavailable. Reopened objects require
/// fresh authority, identity and operation-specific evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedObjectIdentity {
	device: i32,
	physical_fsid: PhysicalFsid,
	inode: NonZeroU64,
	generation: Option<NonZeroU32>,
	birth: ManagedTimestamp,
}

impl ManagedObjectIdentity {
	pub(super) fn from_stat(stat: &Stat, physical_fsid: PhysicalFsid) -> Option<Self> {
		// Zero and Darwin's NODEV sentinel are not data-volume identities.
		if matches!(stat.st_dev, 0 | -1) {
			return None;
		}
		Some(Self {
			device: stat.st_dev,
			physical_fsid,
			inode: NonZeroU64::new(stat.st_ino)?,
			generation: NonZeroU32::new(stat.st_gen),
			birth: ManagedTimestamp::from_stat_parts(stat.st_birthtime, stat.st_birthtime_nsec)?,
		})
	}

	/// Returns the signed native device value for the held object.
	#[must_use]
	pub const fn device(self) -> i32 {
		self.device
	}

	/// Returns the two ordered words of the physical filesystem ID.
	#[must_use]
	pub const fn physical_fsid(self) -> [u32; 2] {
		self.physical_fsid.words()
	}

	/// Returns the native inode number.
	#[must_use]
	pub const fn inode(self) -> NonZeroU64 {
		self.inode
	}

	/// Returns the generation when Darwin exposes a nonzero value.
	#[must_use]
	pub const fn generation(self) -> Option<NonZeroU32> {
		self.generation
	}

	/// Returns the birth-time observation for this inode.
	#[must_use]
	pub const fn birth(self) -> ManagedTimestamp {
		self.birth
	}
}
