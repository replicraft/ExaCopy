use std::fs::File;
#[cfg(feature = "experimental-linux-managed-sync")]
use std::io;
#[cfg(feature = "experimental-linux-managed-sync")]
use std::num::NonZeroU64;
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt as _;

#[cfg(feature = "experimental-linux-managed-sync")]
use exacopy_endpoint::{IoError, MAX_FILE_LENGTH, MAX_INTERRUPTED_RETRIES};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};

use super::{BELOW, FileIdentity, PRIVATE_FILE, SyncProfileStoreError, mount_id};
use crate::linux::SourceTimestamp;
use crate::linux::owner_seed::{KEY_NAME, OWNER_SEED_BYTES};
use crate::linux::source::reopen_regular_without_atime;
#[cfg(feature = "experimental-linux-managed-sync")]
use crate::linux::{ManagedSyncExpectedObject, source::ReadError, sync_preview::unique_mount_id};

#[cfg(feature = "experimental-linux-managed-sync")]
pub(super) struct SelectedPin {
	pub(super) identity: ManagedSyncExpectedObject,
	pub(super) extent: usize,
	pub(super) unique_mount: NonZeroU64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Stamp {
	pub(super) identity: FileIdentity,
	owner: u32,
	group: u32,
	pub(super) extent: usize,
	changed: SourceTimestamp,
	modified: SourceTimestamp,
}

impl Stamp {
	pub(super) fn observe(
		fd: impl AsFd,
		owner: u32,
		mount: u64,
	) -> Result<Self, SyncProfileStoreError> {
		if mount_id(&fd)? != mount {
			return Err(SyncProfileStoreError::Changed);
		}
		Self::from_stat(&fs::fstat(fd)?, owner)
	}

	fn from_stat(stat: &Stat, owner: u32) -> Result<Self, SyncProfileStoreError> {
		if stat.st_uid != owner
			|| stat.st_nlink != 1
			|| FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
			|| Mode::from_raw_mode(stat.st_mode) != PRIVATE_FILE
		{
			return Err(SyncProfileStoreError::Unprotected);
		}
		Ok(Self {
			identity: FileIdentity::from_stat(stat),
			owner: stat.st_uid,
			group: stat.st_gid,
			extent: usize::try_from(stat.st_size)
				.map_err(|_| SyncProfileStoreError::InvalidExtent)?,
			changed: SourceTimestamp::capture(stat.st_ctime, stat.st_ctime_nsec)
				.map_err(|_| SyncProfileStoreError::Changed)?,
			modified: SourceTimestamp::capture(stat.st_mtime, stat.st_mtime_nsec)
				.map_err(|_| SyncProfileStoreError::Changed)?,
		})
	}
}

impl Stamp {
	pub(super) fn require_name(
		self,
		parent: &File,
		name: &[u8],
	) -> Result<(), SyncProfileStoreError> {
		let named = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
		if Self::from_stat(&named, self.owner)? != self {
			return Err(SyncProfileStoreError::Changed);
		}
		Ok(())
	}
}

pub(super) struct Pin {
	name: Vec<u8>,
	file: File,
	pub(super) stamp: Stamp,
	mount: u64,
}

impl Pin {
	pub(super) fn open_seed(
		parent: &File,
		owner: u32,
		mount: u64,
		bytes: &mut [u8; OWNER_SEED_BYTES],
		eof: &mut [u8; 1],
	) -> Result<Self, SyncProfileStoreError> {
		let pin = Self::open(parent, KEY_NAME.to_bytes(), owner, mount)?;
		pin.read(parent, bytes, eof)?;
		Ok(pin)
	}

	pub(super) fn recheck_seed_bytes(
		&self,
		parent: &File,
		expected: &[u8; OWNER_SEED_BYTES],
		scratch: &mut [u8; OWNER_SEED_BYTES],
		eof: &mut [u8; 1],
	) -> Result<(), SyncProfileStoreError> {
		self.read(parent, scratch, eof)?;
		if scratch != expected {
			return Err(SyncProfileStoreError::Changed);
		}
		Ok(())
	}

	pub(super) fn open(
		parent: &File,
		name: &[u8],
		owner: u32,
		mount: u64,
	) -> Result<Self, SyncProfileStoreError> {
		Self::open_checked(parent, name, owner, mount, |_, _| Ok(()))
	}

	fn open_checked(
		parent: &File,
		name: &[u8],
		owner: u32,
		mount: u64,
		check_selected: impl FnOnce(&rustix::fd::OwnedFd, Stamp) -> Result<(), SyncProfileStoreError>,
	) -> Result<Self, SyncProfileStoreError> {
		let named = fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?;
		let stamp = Stamp::from_stat(&named, owner)?;
		// openat2 rejects O_NONBLOCK with an O_PATH descriptor.
		let path = fs::openat2(
			parent,
			name,
			OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
			Mode::empty(),
			BELOW,
		)?;
		if Stamp::observe(&path, owner, mount)? != stamp {
			return Err(SyncProfileStoreError::Changed);
		}
		check_selected(&path, stamp)?;
		let (file, observed) =
			reopen_regular_without_atime(&path).map_err(std::io::Error::other)?;
		if Stamp::from_stat(&observed, owner)? != stamp {
			return Err(SyncProfileStoreError::Changed);
		}
		let pin = Self {
			name: name.to_vec(),
			file,
			stamp,
			mount,
		};
		pin.check(parent)?;
		Ok(pin)
	}

	#[cfg(feature = "experimental-linux-managed-sync")]
	pub(super) fn open_selected(
		parent: &File,
		name: &[u8],
		owner: u32,
		mount: u64,
		expected: SelectedPin,
	) -> Result<Self, SyncProfileStoreError> {
		let pin = Self::open_checked(parent, name, owner, mount, |path, stamp| {
			if !expected.identity.matches(stamp.identity) {
				return Err(SyncProfileStoreError::Changed);
			}
			if stamp.extent != expected.extent {
				return Err(SyncProfileStoreError::InvalidExtent);
			}
			check_unique_mount(path, expected.unique_mount)
		})?;
		pin.check_selected(parent, expected.unique_mount)?;
		Ok(pin)
	}

	#[cfg(feature = "experimental-linux-managed-sync")]
	pub(super) fn read_selected(
		&self,
		parent: &File,
		unique_mount: NonZeroU64,
		output: &mut [u8],
	) -> Result<(), SyncProfileStoreError> {
		if output.len() != self.stamp.extent {
			return Err(SyncProfileStoreError::InvalidExtent);
		}
		self.check_selected(parent, unique_mount)?;
		read_bounded(output, |offset, bytes| self.file.read_at(bytes, offset))?;
		self.check_selected(parent, unique_mount)
	}

	#[cfg(feature = "experimental-linux-managed-sync")]
	pub(super) fn check_selected(
		&self,
		parent: &File,
		unique_mount: NonZeroU64,
	) -> Result<(), SyncProfileStoreError> {
		self.check(parent)?;
		let named = fs::openat2(
			parent,
			self.name.as_slice(),
			OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
			Mode::empty(),
			BELOW,
		)?;
		if Stamp::observe(&named, self.stamp.owner, self.mount)? != self.stamp {
			return Err(SyncProfileStoreError::Changed);
		}
		check_unique_mount(named, unique_mount)?;
		check_unique_mount(&self.file, unique_mount)
	}

	pub(super) fn read(
		&self,
		parent: &File,
		output: &mut [u8],
		eof: &mut [u8; 1],
	) -> Result<(), SyncProfileStoreError> {
		if output.len() != self.stamp.extent {
			return Err(SyncProfileStoreError::InvalidExtent);
		}
		self.check(parent)?;
		self.file.read_exact_at(output, 0)?;
		let end = u64::try_from(output.len()).map_err(|_| SyncProfileStoreError::InvalidExtent)?;
		if self.file.read_at(eof, end)? != 0 {
			return Err(SyncProfileStoreError::Changed);
		}
		self.check(parent)
	}

	fn check(&self, parent: &File) -> Result<(), SyncProfileStoreError> {
		if Stamp::observe(&self.file, self.stamp.owner, self.mount)? != self.stamp {
			return Err(SyncProfileStoreError::Changed);
		}
		self.stamp.require_name(parent, &self.name)
	}
}

#[cfg(feature = "experimental-linux-managed-sync")]
fn check_unique_mount(fd: impl AsFd, expected: NonZeroU64) -> Result<(), SyncProfileStoreError> {
	if unique_mount_id(fd).map_err(std::io::Error::other)? != expected {
		return Err(SyncProfileStoreError::Changed);
	}
	Ok(())
}

// The prepared-slot read uses one interruption allowance across short reads and
// the terminal one-byte probe. A successful short read never resets it.
#[cfg(feature = "experimental-linux-managed-sync")]
fn read_bounded(
	output: &mut [u8],
	mut read_at: impl FnMut(u64, &mut [u8]) -> io::Result<usize>,
) -> Result<(), SyncProfileStoreError> {
	let length = output.len();
	let invalid_range = || io::Error::other(IoError::InvalidRange { offset: 0, length });
	let end = u64::try_from(length)
		.ok()
		.filter(|&end| end <= MAX_FILE_LENGTH)
		.ok_or_else(invalid_range)?;

	let mut remaining_retries = MAX_INTERRUPTED_RETRIES;
	let mut read = |offset, bytes: &mut [u8]| loop {
		match read_at(offset, bytes) {
			Err(error) if error.kind() == io::ErrorKind::Interrupted && remaining_retries > 0 => {
				remaining_retries -= 1;
			}
			result => break result,
		}
	};

	let mut done = 0;
	while done < length {
		let offset = u64::try_from(done).map_err(|_| invalid_range())?;
		let remaining = &mut output[done..];
		let count = read(offset, remaining)
			.map_err(|source| io::Error::other(IoError::System { offset, source }))?;
		if count == 0 {
			return Err(io::Error::other(IoError::UnexpectedEof { offset }).into());
		}
		if count > remaining.len() {
			return Err(io::Error::other(IoError::InvalidTransferCount {
				offset,
				count,
				remaining: remaining.len(),
			})
			.into());
		}
		done += count;
	}

	let count = read(end, &mut [0]).map_err(|error| io::Error::other(ReadError::System(error)))?;
	if count != 0 {
		return Err(io::Error::other(ReadError::UnexpectedDataAfterEnd).into());
	}
	Ok(())
}

#[cfg(all(test, feature = "experimental-linux-managed-sync"))]
mod tests {
	use std::io;

	use exacopy_endpoint::IoError;
	use rustix::io::Errno;

	use super::{ReadError, SyncProfileStoreError, read_bounded};

	#[test]
	fn prepared_slot_read_budget_does_not_reset_after_progress() {
		let mut output = [0xa5; 4];
		let mut first = 0;
		let mut later = 0;
		let error = read_bounded(&mut output[1..3], |offset, remaining| match offset {
			0 => {
				assert_eq!(remaining.len(), 2);
				first += 1;
				if first <= 8 {
					return Err(Errno::INTR.into());
				}
				remaining[0] = b'A';
				Ok(1)
			}
			1 => {
				assert_eq!(remaining.len(), 1);
				later += 1;
				Err(Errno::INTR.into())
			}
			_ => panic!("read advanced past an unconfirmed position"),
		})
		.unwrap_err();
		assert_eq!((first, later), (9, 9));
		assert_eq!(output, [0xa5, b'A', 0xa5, 0xa5]);
		let SyncProfileStoreError::System(error) = error else {
			panic!("expected positioned read failure");
		};
		let Some(IoError::System { offset: 1, source }) = error
			.get_ref()
			.and_then(|cause| cause.downcast_ref::<IoError>())
		else {
			panic!("expected the original system error at the next unread byte");
		};
		assert_eq!(source.kind(), io::ErrorKind::Interrupted);
		assert_eq!(source.raw_os_error(), Some(Errno::INTR.raw_os_error()));
	}

	#[test]
	fn prepared_slot_read_budget_is_shared_with_terminal_probe() {
		for terminal_interruptions in [8, 9] {
			let mut output = [0xa5; 4];
			let mut first = 0;
			let mut progress = 0;
			let mut terminal = 0;
			let result = read_bounded(&mut output[1..3], |offset, remaining| match offset {
				0 => {
					assert_eq!(remaining.len(), 2);
					first += 1;
					if first <= 8 {
						return Err(Errno::INTR.into());
					}
					remaining[0] = b'A';
					Ok(1)
				}
				1 => {
					assert_eq!(remaining.len(), 1);
					progress += 1;
					remaining[0] = b'B';
					Ok(1)
				}
				2 => {
					assert_eq!(remaining.len(), 1);
					terminal += 1;
					if terminal <= terminal_interruptions {
						Err(Errno::INTR.into())
					} else {
						Ok(0)
					}
				}
				_ => panic!("read past the exact one-byte EOF probe"),
			});
			assert_eq!((first, progress, terminal), (9, 1, 9));
			assert_eq!(output, [0xa5, b'A', b'B', 0xa5]);
			if terminal_interruptions == 8 {
				result.unwrap();
				continue;
			}
			let Err(SyncProfileStoreError::System(error)) = result else {
				panic!("expected the EOF probe to exhaust the combined allowance");
			};
			let Some(ReadError::System(source)) = error
				.get_ref()
				.and_then(|cause| cause.downcast_ref::<ReadError>())
			else {
				panic!("expected the original terminal probe system error");
			};
			assert_eq!(source.kind(), io::ErrorKind::Interrupted);
			assert_eq!(source.raw_os_error(), Some(Errno::INTR.raw_os_error()));
		}
	}
}
