use exacopy_endpoint::MAX_FILE_LENGTH;
use rustix::fs::{FileType, Mode, Stat};

use super::ReadError;
use crate::linux::handle::FileIdentity;

/// Basic identity and metadata captured through the held regular-file descriptor.
///
/// These fields describe observations of a live inode. The filesystem can
/// change between observations, and the fields returned by one stat call can
/// reflect different moments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceObservation {
	identity: FileIdentity,
	length: u64,
	mode: u32,
	owner: u32,
	group: u32,
	link_count: u64,
	accessed_at: SourceTimestamp,
	modified_at: SourceTimestamp,
	changed_at: SourceTimestamp,
}

impl SourceObservation {
	pub(in crate::linux) fn capture(stat: &Stat) -> Result<Self, ReadError> {
		if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
			return Err(ReadError::NotRegularFile);
		}
		let length = u64::try_from(stat.st_size)
			.ok()
			.filter(|length| *length <= MAX_FILE_LENGTH)
			.ok_or(ReadError::InvalidLength)?;
		#[cfg_attr(
			all(target_arch = "x86_64", target_pointer_width = "64"),
			expect(
				clippy::useless_conversion,
				reason = "Linux stat link counts vary by ABI"
			)
		)]
		let link_count = u64::from(stat.st_nlink);
		Ok(Self {
			identity: FileIdentity::from_stat(stat),
			length,
			mode: Mode::from_raw_mode(stat.st_mode).as_raw_mode(),
			owner: stat.st_uid,
			group: stat.st_gid,
			link_count,
			accessed_at: SourceTimestamp::capture(stat.st_atime, stat.st_atime_nsec)?,
			modified_at: SourceTimestamp::capture(stat.st_mtime, stat.st_mtime_nsec)?,
			changed_at: SourceTimestamp::capture(stat.st_ctime, stat.st_ctime_nsec)?,
		})
	}

	pub(in crate::linux) fn recheck(self, current: Self) -> Result<(), ReadError> {
		if self.identity != current.identity {
			return Err(ReadError::IdentityChanged);
		}
		// Reading the source may advance atime. Retain the timestamp initially
		// observed for metadata handling while excluding it from this comparison.
		let comparable = Self {
			accessed_at: self.accessed_at,
			..current
		};
		if comparable != self {
			return Err(ReadError::SourceChanged);
		}
		Ok(())
	}

	/// The identity of the held source inode.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.identity
	}

	/// The observed logical byte length of the unnamed stream.
	#[must_use]
	pub fn len(&self) -> u64 {
		self.length
	}

	/// Whether the unnamed stream was empty.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.length == 0
	}

	/// The observed mode bits, including set-user-ID, set-group-ID and sticky bits.
	#[must_use]
	pub fn mode(&self) -> u32 {
		self.mode
	}

	/// The observed owner user ID in the caller's user namespace.
	#[must_use]
	pub fn owner(&self) -> u32 {
		self.owner
	}

	/// The observed owner group ID in the caller's user namespace.
	#[must_use]
	pub fn group(&self) -> u32 {
		self.group
	}

	/// The observed number of hard links to the inode.
	#[must_use]
	pub fn link_count(&self) -> u64 {
		self.link_count
	}

	/// The access time before adapter data reads.
	#[must_use]
	pub fn accessed_at(&self) -> SourceTimestamp {
		self.accessed_at
	}

	/// The observed content modification time.
	#[must_use]
	pub fn modified_at(&self) -> SourceTimestamp {
		self.modified_at
	}

	/// The observed inode change time.
	#[must_use]
	pub fn changed_at(&self) -> SourceTimestamp {
		self.changed_at
	}
}

/// A Linux inode timestamp with signed seconds and a nanosecond fraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceTimestamp {
	seconds: i64,
	nanoseconds: u32,
}

impl SourceTimestamp {
	fn capture(seconds: i64, nanoseconds: impl TryInto<u32>) -> Result<Self, ReadError> {
		const NANOS_PER_SECOND: u32 = 1_000_000_000;
		let nanoseconds = nanoseconds
			.try_into()
			.ok()
			.filter(|nanos| *nanos < NANOS_PER_SECOND)
			.ok_or(ReadError::InvalidTimestamp)?;
		Ok(Self {
			seconds,
			nanoseconds,
		})
	}

	/// Whole seconds since the Unix epoch.
	#[must_use]
	pub fn seconds(self) -> i64 {
		self.seconds
	}

	/// The nonnegative nanosecond fraction of the current second.
	#[must_use]
	pub fn nanoseconds(self) -> u32 {
		self.nanoseconds
	}
}
