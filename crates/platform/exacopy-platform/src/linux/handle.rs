use std::os::fd::AsFd;

use rustix::fs::{self, AtFlags, Dev, Stat, StatxFlags};
use rustix::io::{self, Errno};

/// The device and inode observed through a live Linux file descriptor.
///
/// Equality identifies hard-linked names for the same object. Compare identities
/// while their descriptors are live, since a filesystem can reuse an inode
/// after the last reference to it is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
	device: Dev,
	inode: u64,
}

impl FileIdentity {
	/// Returns the raw Linux device identifier of the observed inode.
	#[must_use]
	pub const fn device(self) -> u64 {
		self.device
	}

	/// Returns the inode number of the observed file or directory.
	#[must_use]
	pub const fn inode(self) -> u64 {
		self.inode
	}

	pub(super) fn from_stat(stat: &Stat) -> Self {
		Self {
			device: stat.st_dev,
			inode: stat.st_ino,
		}
	}
}

pub(super) fn file_identity(fd: impl AsFd) -> io::Result<FileIdentity> {
	fs::fstat(fd).map(|stat| FileIdentity::from_stat(&stat))
}

pub(super) fn mount_id(fd: impl AsFd) -> io::Result<u64> {
	mount_id_with_flags(fd, AtFlags::EMPTY_PATH)
}

// A last-component O_PATH pin can refer to a symlink itself.
pub(super) fn mount_id_no_follow(fd: impl AsFd) -> io::Result<u64> {
	mount_id_with_flags(fd, AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW)
}

fn mount_id_with_flags(fd: impl AsFd, flags: AtFlags) -> io::Result<u64> {
	let stat = fs::statx(fd, c"", flags, StatxFlags::MNT_ID)?;
	if stat.stx_mask & StatxFlags::MNT_ID.bits() == 0 {
		return Err(Errno::NOTSUP);
	}
	Ok(stat.stx_mnt_id)
}
