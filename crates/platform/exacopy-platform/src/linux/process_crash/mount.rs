use std::os::fd::AsFd;

use rustix::fs::{self, AtFlags, StatVfsMountFlags, StatxFlags};
use rustix::io::Errno;

use super::ProcessCrashProfileError;
use crate::linux::handle::{file_identity, mount_id};
use crate::linux::mount_observation::{MountRecord, nonzero_decimal};

// Linux 6.8 <uapi/linux/stat.h>. This flag is absent from rustix 1.1.6.
const MOUNT_ID_UNIQUE: StatxFlags = StatxFlags::from_bits_retain(0x4000);
// Linux <uapi/linux/magic.h>. The magic is shared with ext2/ext3. Mountinfo
// separately identifies the precise filesystem type.
const EXT_SUPER_MAGIC: rustix::fs::FsWord = 0xef53;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Mount {
	pub(super) id: u64,
	pub(super) unique_id: u64,
	pub(super) device: u64,
}

pub(super) fn observe(fd: impl AsFd) -> Result<Mount, ProcessCrashProfileError> {
	let fd = fd.as_fd();
	if fs::fstatfs(fd)?.f_type != EXT_SUPER_MAGIC
		|| fs::fstatvfs(fd)?.f_flag.contains(StatVfsMountFlags::RDONLY)
	{
		return Err(ProcessCrashProfileError::UnsupportedMount);
	}
	let id = mount_id(fd).map_err(mount_error)?;
	// The ordinary ID pairs with mountinfo. Request unique ID separately
	// because statx returns only one stx_mnt_id field.
	let stat = fs::statx(fd, c"", AtFlags::EMPTY_PATH, MOUNT_ID_UNIQUE).map_err(mount_error)?;
	if id == 0 || stat.stx_mnt_id == 0 || stat.stx_mask & MOUNT_ID_UNIQUE.bits() == 0 {
		return Err(ProcessCrashProfileError::UnsupportedMount);
	}
	Ok(Mount {
		id,
		unique_id: stat.stx_mnt_id,
		device: file_identity(fd)?.device(),
	})
}

fn mount_error(error: Errno) -> ProcessCrashProfileError {
	match error {
		Errno::NOTSUP | Errno::NOSYS | Errno::INVAL => ProcessCrashProfileError::UnsupportedMount,
		_ => error.into(),
	}
}

pub(super) fn is_fixture_mount(record: &MountRecord<'_>, mount: Mount) -> bool {
	record.id == mount.id
		&& record.parent != 0
		&& record.device == (fs::major(mount.device), fs::minor(mount.device))
		&& record.root == b"/"
		&& record.mount_point == b"/"
		&& record.mount_options == b"rw,relatime"
		&& matches!(record.optional_fields.as_slice(), [field] if is_shared(field))
		&& record.filesystem == b"ext4"
		&& record.source == b"/dev/vda1"
		&& record.super_options == b"rw,discard,errors=remount-ro,commit=30"
}

fn is_shared(field: &[u8]) -> bool {
	// The group ID is a namespace-local kernel number.
	field
		.strip_prefix(b"shared:")
		.and_then(nonzero_decimal)
		.is_some()
}
