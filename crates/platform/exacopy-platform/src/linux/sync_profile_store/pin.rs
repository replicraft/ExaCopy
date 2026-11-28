use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt as _;

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};

use super::{BELOW, FileIdentity, PRIVATE_FILE, SyncProfileStoreError, mount_id};
use crate::linux::SourceTimestamp;
use crate::linux::owner_seed::{KEY_NAME, OWNER_SEED_BYTES};
use crate::linux::source::reopen_regular_without_atime;

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
