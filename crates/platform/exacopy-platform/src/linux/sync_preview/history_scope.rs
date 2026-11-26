use std::num::NonZeroU64;
use std::os::fd::AsFd;

use exacopy_endpoint::UnixComponent;
use rustix::fs::{self, AtFlags, Mode, OFlags, StatxFlags};

use super::{CHILD_RESOLUTION, FileIdentity, SyncPreviewError, SyncPreviewPair};
use crate::linux::handle::{file_identity, mount_id};
use crate::linux::mount_observation::ProcMounts;
use crate::linux::process_crash::{KERNEL_BOOT_ID_BYTES, parse_boot_id};

// Fixed Linux UAPI attributes unavailable as named flags in the pinned rustix.
const MOUNT_ID_UNIQUE: StatxFlags = StatxFlags::from_bits_retain(0x4000);
const EXT_SUPER_MAGIC: fs::FsWord = 0xef53;
const ENCRYPT_DIRECTORY: u32 = 0x0000_0800;
const CASEFOLD_DIRECTORY: u32 = 0x4000_0000;

/// Live Linux identifiers needed to compare one current endpoint to history.
///
/// A fact supplies no managed cooperation lease, owner mapping or mutation
/// authority. Trusted composition must admit those profile requirements separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncHistoryLocation<'selection> {
	/// Current boot ID from the verified procfs mount.
	pub boot: [u8; 16],
	/// Held mount namespace identity.
	pub mount_namespace: FileIdentity,
	/// Held user namespace identity.
	pub user_namespace: FileIdentity,
	/// Unique mount identity under this boot.
	pub unique_mount: NonZeroU64,
	/// Held common parent identity.
	pub parent: FileIdentity,
	/// Held direct child directory identity.
	pub root: FileIdentity,
	/// Exact raw directory basename under the held parent.
	pub root_name: UnixComponent<'selection>,
}

impl<'view> SyncPreviewPair<'view, '_> {
	/// Re-observes native facts of the currently held ext4 pair.
	///
	/// The caller must independently admit the managed cooperation and UID/GID
	/// mapping contract. This read does not issue a historical profile proof by
	/// itself. The same held pair supplies the subject and its observations.
	///
	/// # Errors
	/// Refuses an unsupported mount or naming mode, missing unique identities,
	/// and a changed scope or incomplete subject recheck.
	pub fn recheck_history_location(
		&self,
	) -> Result<(UnixComponent<'view>, [SyncHistoryLocation<'view>; 2]), SyncPreviewError> {
		self.recheck()?;
		let first = self.observe_history_location()?;
		self.recheck()?;
		let second = self.observe_history_location()?;
		if first != second {
			return Err(SyncPreviewError::Changed);
		}
		Ok((self.subject, first))
	}

	fn observe_history_location(
		&self,
	) -> Result<[SyncHistoryLocation<'view>; 2], SyncPreviewError> {
		let pair = self.roots;
		let proc = ProcMounts::open().map_err(SyncPreviewError::System)?;
		let boot = parse_boot_id(
			&proc
				.root_file(c"sys/kernel/random/boot_id", KERNEL_BOOT_ID_BYTES)
				.map_err(SyncPreviewError::System)?,
		)
		.ok_or(SyncPreviewError::UnsupportedNamespace)?;
		let namespaces = pair.namespaces.facts();
		let table = proc.mount_table().map_err(SyncPreviewError::System)?;
		let observed_mount = table
			.whole_filesystem_mount(&pair.parent)
			.map_err(SyncPreviewError::System)?;
		let record = table
			.record(observed_mount)
			.ok_or(SyncPreviewError::UnsupportedMount)?;
		if observed_mount != pair.mount
			|| record.filesystem != b"ext4"
			|| fs::fstatfs(&pair.parent)?.f_type != EXT_SUPER_MAGIC
		{
			return Err(SyncPreviewError::UnsupportedMount);
		}
		let unique_mount = unique_mount_id(&pair.parent)?;
		check_directory(&pair.parent, pair.parent_identity, pair.mount, unique_mount)?;
		let [left, right] = &pair.roots;
		check_directory(left.directory(), left.identity(), pair.mount, unique_mount)?;
		check_directory(
			right.directory(),
			right.identity(),
			pair.mount,
			unique_mount,
		)?;
		let [left_name, right_name] = pair.names;
		let fact = |root, root_name| SyncHistoryLocation {
			boot,
			mount_namespace: namespaces.mount,
			user_namespace: namespaces.user,
			unique_mount,
			parent: pair.parent_identity,
			root,
			root_name,
		};
		Ok([
			fact(left.identity(), left_name),
			fact(right.identity(), right_name),
		])
	}
}

fn unique_mount_id(descriptor: impl AsFd) -> Result<NonZeroU64, SyncPreviewError> {
	let stat = fs::statx(descriptor, c"", AtFlags::EMPTY_PATH, MOUNT_ID_UNIQUE)?;
	if stat.stx_mask & MOUNT_ID_UNIQUE.bits() == 0 {
		return Err(SyncPreviewError::UnsupportedMount);
	}
	NonZeroU64::new(stat.stx_mnt_id).ok_or(SyncPreviewError::UnsupportedMount)
}

fn check_directory(
	descriptor: impl AsFd,
	expected: FileIdentity,
	mount: u64,
	unique_mount: NonZeroU64,
) -> Result<(), SyncPreviewError> {
	let readable = fs::openat2(
		descriptor,
		c".",
		OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
		Mode::empty(),
		CHILD_RESOLUTION,
	)?;
	if expected.inode() == 0
		|| file_identity(&readable)? != expected
		|| mount_id(&readable)? != mount
		|| unique_mount_id(&readable)? != unique_mount
	{
		return Err(SyncPreviewError::Changed);
	}
	let flags = fs::ioctl_getflags(&readable)?.bits();
	if flags & (ENCRYPT_DIRECTORY | CASEFOLD_DIRECTORY) != 0 {
		return Err(SyncPreviewError::UnsupportedHistoryNamePolicy);
	}
	Ok(())
}
