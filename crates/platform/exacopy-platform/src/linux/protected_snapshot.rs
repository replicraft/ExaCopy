use std::fs::File;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use exacopy_endpoint::{IoError, UnixComponent};
use rustix::fs::{self, FileType, FlockOperation, FsWord, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;
use rustix::process::{geteuid, getuid};

use crate::protected_snapshot::{
	MAX_PROTECTED_SNAPSHOT_BYTES, ProtectedSnapshotError, checked_components,
};

use super::handle::{FileIdentity, mount_id};
use super::mount_observation::MountObservations;
use super::source::{ReadError, ReadRoot, SourceFile, SourceTimestamp};

#[cfg(test)]
mod tests;

// Linux <uapi/linux/magic.h>. Mountinfo also identifies ext4 specifically.
const EXT_SUPER_MAGIC: FsWord = 0xef53;
const XFS_SUPER_MAGIC: FsWord = 0x5846_5342;
const DIRECTORY_FLAGS: OFlags = OFlags::PATH.union(OFlags::CLOEXEC).union(OFlags::DIRECTORY);
const DIRECTORY_READ_FLAGS: OFlags = OFlags::RDONLY
	.union(OFlags::CLOEXEC)
	.union(OFlags::DIRECTORY);
const RESOLUTION: ResolveFlags = ResolveFlags::BENEATH
	.union(ResolveFlags::NO_SYMLINKS)
	.union(ResolveFlags::NO_MAGICLINKS)
	.union(ResolveFlags::NO_XDEV);
const PRIVATE_DIRECTORY_MODE: Mode = Mode::RUSR.union(Mode::WUSR).union(Mode::XUSR);
const PRIVATE_FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);
const OTHER_WRITE: Mode = Mode::WGRP.union(Mode::WOTH);
const READBACK_CHUNK_BYTES: usize = 16 * 1024;

pub(crate) fn read(path: &Path) -> Result<Vec<u8>, ProtectedSnapshotError> {
	read_checked(path, MAX_PROTECTED_SNAPSHOT_BYTES, read_twice)
}

pub(crate) fn read_into(
	path: &Path,
	bytes: &mut [u8],
	readback: &mut [u8],
) -> Result<usize, ProtectedSnapshotError> {
	if readback.is_empty() {
		return Err(ProtectedSnapshotError::Unavailable);
	}
	let limit = bytes.len().min(MAX_PROTECTED_SNAPSHOT_BYTES);
	read_checked(path, limit, |root, name, file, length| {
		read_twice_into(root, name, file, &mut bytes[..length], readback)?;
		Ok(length)
	})
}

fn read_checked<T>(
	path: &Path,
	limit: usize,
	load: impl FnOnce(
		&ReadRoot,
		UnixComponent<'_>,
		&SourceFile,
		usize,
	) -> Result<T, ProtectedSnapshotError>,
) -> Result<T, ProtectedSnapshotError> {
	let components = checked_components(path.as_os_str().as_bytes())?;
	let (&name, ancestors) = components
		.split_last()
		.ok_or(ProtectedSnapshotError::InvalidPath)?;
	let owner = current_owner()?;
	let root = hold_root(owner)?;
	let admitted_mount = root_mount(&root.descriptor)?;
	let mut chain = vec![root];
	for &ancestor in ancestors {
		let parent = chain.last().ok_or(ProtectedSnapshotError::InvalidPath)?;
		let descriptor = open_child(&parent.descriptor, ancestor)?;
		chain.push(HeldDirectory::new(descriptor, owner)?);
	}

	let parent = chain.last().ok_or(ProtectedSnapshotError::InvalidPath)?;
	let root = parent.lock_private(owner)?;
	let file = root.open_regular(name).map_err(read_error)?;
	let length = protected_length(&file, owner)?;
	if length > limit {
		return Err(ProtectedSnapshotError::TooLarge);
	}
	let bytes = load(&root, name, &file, length)?;

	recheck_chain(&chain, ancestors, owner, admitted_mount)?;
	check_file(&root, name, &file)?;
	if current_owner()? != owner {
		return Err(ProtectedSnapshotError::Changed);
	}
	Ok(bytes)
}

fn current_owner() -> Result<u32, ProtectedSnapshotError> {
	let uid = geteuid();
	if uid.is_root() || uid != getuid() {
		return Err(ProtectedSnapshotError::Unsupported);
	}
	Ok(uid.as_raw())
}

fn hold_root(owner: u32) -> Result<HeldDirectory, ProtectedSnapshotError> {
	let descriptor = fs::openat2(
		fs::CWD,
		c"/",
		DIRECTORY_FLAGS,
		Mode::empty(),
		ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
	)
	.map_err(lookup_error)?;
	HeldDirectory::new(descriptor, owner)
}

fn root_mount(descriptor: &OwnedFd) -> Result<u64, ProtectedSnapshotError> {
	let table = MountObservations::capture().map_err(|_| ProtectedSnapshotError::Unavailable)?;
	let id = table
		.whole_filesystem_mount(descriptor)
		.map_err(|_| ProtectedSnapshotError::Unsupported)?;
	let record = table
		.record(id)
		.ok_or(ProtectedSnapshotError::Unsupported)?;
	let filesystem = fs::fstatfs(descriptor).map_err(lookup_error)?.f_type;
	if record.mount_point != b"/"
		|| !matches!(
			(record.filesystem, filesystem),
			(b"ext4", EXT_SUPER_MAGIC) | (b"xfs", XFS_SUPER_MAGIC)
		) {
		return Err(ProtectedSnapshotError::Unsupported);
	}
	Ok(id)
}

fn open_child(
	parent: &OwnedFd,
	name: UnixComponent<'_>,
) -> Result<OwnedFd, ProtectedSnapshotError> {
	fs::openat2(
		parent,
		name.as_bytes(),
		DIRECTORY_FLAGS,
		Mode::empty(),
		RESOLUTION,
	)
	.map_err(lookup_error)
}

struct HeldDirectory {
	descriptor: OwnedFd,
	observation: DirectoryObservation,
}

impl HeldDirectory {
	fn new(descriptor: OwnedFd, owner: u32) -> Result<Self, ProtectedSnapshotError> {
		let observation = DirectoryObservation::observe(&descriptor, owner)?;
		Ok(Self {
			descriptor,
			observation,
		})
	}

	fn lock_private(&self, owner: u32) -> Result<ReadRoot, ProtectedSnapshotError> {
		if self.observation.uid != owner || self.observation.mode != PRIVATE_DIRECTORY_MODE {
			return Err(ProtectedSnapshotError::Unprotected);
		}
		// Opening dot separately keeps this shared lock independent of every other consumer's lock.
		let descriptor = fs::openat2(
			&self.descriptor,
			c".",
			DIRECTORY_READ_FLAGS,
			Mode::empty(),
			RESOLUTION,
		)
		.map_err(lookup_error)?;
		fs::flock(&descriptor, FlockOperation::NonBlockingLockShared).map_err(|error| {
			if error == Errno::WOULDBLOCK {
				ProtectedSnapshotError::Busy
			} else {
				ProtectedSnapshotError::Unavailable
			}
		})?;
		self.recheck(&descriptor, owner)?;
		ReadRoot::from_directory(File::from(descriptor)).map_err(read_error)
	}

	fn recheck(&self, descriptor: &OwnedFd, owner: u32) -> Result<(), ProtectedSnapshotError> {
		let observed = DirectoryObservation::observe(descriptor, owner)?;
		if observed != self.observation {
			return Err(ProtectedSnapshotError::Changed);
		}
		Ok(())
	}
}

#[derive(PartialEq, Eq)]
struct DirectoryObservation {
	identity: FileIdentity,
	mount: u64,
	uid: u32,
	gid: u32,
	mode: Mode,
	links: u64,
	size: i64,
	mtime: SourceTimestamp,
	ctime: SourceTimestamp,
}

impl DirectoryObservation {
	fn observe(descriptor: impl AsFd, owner: u32) -> Result<Self, ProtectedSnapshotError> {
		let fd = descriptor.as_fd();
		let stat = fs::fstat(fd).map_err(lookup_error)?;
		let mode = Mode::from_raw_mode(stat.st_mode);
		// Ext4 and XFS expose the effective POSIX ACL mask as the group-class bits.
		if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
			|| (stat.st_uid != 0 && stat.st_uid != owner)
			|| mode.intersects(OTHER_WRITE)
		{
			return Err(ProtectedSnapshotError::Unprotected);
		}
		#[cfg_attr(
			all(target_arch = "x86_64", target_pointer_width = "64"),
			expect(
				clippy::useless_conversion,
				reason = "Linux stat link counts vary by ABI"
			)
		)]
		let links = u64::from(stat.st_nlink);
		Ok(Self {
			identity: FileIdentity::from_stat(&stat),
			mount: mount_id(fd).map_err(lookup_error)?,
			uid: stat.st_uid,
			gid: stat.st_gid,
			mode,
			links,
			size: stat.st_size,
			mtime: SourceTimestamp::capture(stat.st_mtime, stat.st_mtime_nsec)
				.map_err(read_error)?,
			ctime: SourceTimestamp::capture(stat.st_ctime, stat.st_ctime_nsec)
				.map_err(read_error)?,
		})
	}
}

fn recheck_chain(
	chain: &[HeldDirectory],
	names: &[UnixComponent<'_>],
	owner: u32,
	admitted_mount: u64,
) -> Result<(), ProtectedSnapshotError> {
	for (pair, &name) in chain.windows(2).zip(names).rev() {
		let parent = &pair[0];
		let child = &pair[1];
		child.recheck(&child.descriptor, owner)?;
		let named =
			open_child(&parent.descriptor, name).map_err(|_| ProtectedSnapshotError::Changed)?;
		child.recheck(&named, owner)?;
	}
	let root = chain.first().ok_or(ProtectedSnapshotError::InvalidPath)?;
	root.recheck(&root.descriptor, owner)?;
	let current_root = hold_root(owner)?;
	root.recheck(&current_root.descriptor, owner)?;
	if root_mount(&current_root.descriptor)? != admitted_mount {
		return Err(ProtectedSnapshotError::Changed);
	}
	Ok(())
}

fn protected_length(file: &SourceFile, owner: u32) -> Result<usize, ProtectedSnapshotError> {
	let observed = file.observation();
	if Mode::from_raw_mode(observed.mode()) != PRIVATE_FILE_MODE
		|| observed.owner() != owner
		|| observed.link_count() != 1
	{
		return Err(ProtectedSnapshotError::Unprotected);
	}
	usize::try_from(observed.len())
		.ok()
		.filter(|&length| length <= MAX_PROTECTED_SNAPSHOT_BYTES)
		.ok_or(ProtectedSnapshotError::TooLarge)
}

fn read_twice(
	root: &ReadRoot,
	name: UnixComponent<'_>,
	file: &SourceFile,
	length: usize,
) -> Result<Vec<u8>, ProtectedSnapshotError> {
	let mut bytes = vec![0; length];
	let mut readback = [0; READBACK_CHUNK_BYTES];
	read_twice_into(root, name, file, &mut bytes, &mut readback)?;
	Ok(bytes)
}

fn read_twice_into(
	root: &ReadRoot,
	name: UnixComponent<'_>,
	file: &SourceFile,
	bytes: &mut [u8],
	readback: &mut [u8],
) -> Result<(), ProtectedSnapshotError> {
	check_file(root, name, file)?;
	file.read_exact_at(0, bytes).map_err(read_error)?;
	file.check_logical_eof().map_err(read_error)?;
	check_file(root, name, file)?;

	let mut offset = 0_u64;
	for expected in bytes.chunks(readback.len()) {
		let chunk = &mut readback[..expected.len()];
		file.read_exact_at(offset, chunk).map_err(read_error)?;
		if chunk != expected {
			return Err(ProtectedSnapshotError::Changed);
		}
		let count = u64::try_from(chunk.len()).map_err(|_| ProtectedSnapshotError::TooLarge)?;
		offset = offset
			.checked_add(count)
			.ok_or(ProtectedSnapshotError::TooLarge)?;
	}
	file.check_logical_eof().map_err(read_error)?;
	check_file(root, name, file)
}

fn check_file(
	root: &ReadRoot,
	name: UnixComponent<'_>,
	file: &SourceFile,
) -> Result<(), ProtectedSnapshotError> {
	file.recheck_observation().map_err(read_error)?;
	root.recheck_regular_name(name, file).map_err(read_error)
}

fn lookup_error(error: Errno) -> ProtectedSnapshotError {
	match error {
		Errno::XDEV | Errno::NOSYS | Errno::NOTSUP => ProtectedSnapshotError::Unsupported,
		Errno::LOOP | Errno::NOTDIR => ProtectedSnapshotError::Unprotected,
		_ => ProtectedSnapshotError::Unavailable,
	}
}

fn read_error(error: ReadError) -> ProtectedSnapshotError {
	match error {
		ReadError::IdentityChanged
		| ReadError::SourceChanged
		| ReadError::UnexpectedDataAfterEnd
		| ReadError::Io(IoError::UnexpectedEof { .. }) => ProtectedSnapshotError::Changed,
		ReadError::NotDirectory | ReadError::NotRegularFile => ProtectedSnapshotError::Unprotected,
		ReadError::UnsupportedProcfs => ProtectedSnapshotError::Unsupported,
		ReadError::System(error) => lookup_error(Errno::from_io_error(&error).unwrap_or(Errno::IO)),
		_ => ProtectedSnapshotError::Unavailable,
	}
}
