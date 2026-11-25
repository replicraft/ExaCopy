use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::AsFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::process;

use exacopy_endpoint::UnixComponent;
use rustix::fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags, Stat};
use rustix::io::Errno;

#[allow(unsafe_code, reason = "bounded descriptor ACL attributes on Darwin")]
mod acl;
mod error;
mod file;
#[allow(
	unsafe_code,
	reason = "bounded descriptor xattr and resource-fork queries"
)]
mod metadata;
mod observation;
#[allow(
	unsafe_code,
	reason = "bounded descriptor and relative-name physical FSID attributes on Darwin"
)]
mod physical_fsid;
#[path = "publication/mod.rs"]
pub mod publication;
#[path = "staging/mod.rs"]
pub mod staging;
#[cfg(test)]
mod tests;
#[allow(
	unsafe_code,
	reason = "scoped Darwin per-thread materialization policy"
)]
mod thread_policy;
#[allow(
	unsafe_code,
	reason = "bounded descriptor volume capability query on Darwin"
)]
mod volume;

pub use error::ManagedReadError;
pub use file::{ManagedRegularFile, ManagedSourceIdentities};
pub use metadata::{BasicMetadata, BasicMetadataError};
pub use observation::{ManagedObjectIdentity, ManagedTimestamp};

use self::physical_fsid::PhysicalFsid;
use self::thread_policy::with_materialization_disabled;

const DIRECTORY_MODE: Mode = Mode::RUSR.union(Mode::WUSR).union(Mode::XUSR);
const FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);
const APFS_NAME: [libc::c_char; 5] = [b'a' as _, b'p' as _, b'f' as _, b's' as _, 0];
const EVENT_ONLY: OFlags = OFlags::from_bits_retain(libc::O_EVTONLY as u32);
const DIRECTORY_OPEN: OFlags = OFlags::RDONLY
	.union(OFlags::DIRECTORY)
	.union(OFlags::NOFOLLOW)
	.union(OFlags::CLOEXEC);

// Darwin <sys/stat.h>. Refuse firmlinks and dataless File Provider objects.
const SF_FIRMLINK: u32 = 0x0080_0000;
const SF_DATALESS: u32 = 0x4000_0000;
const UNSUPPORTED_OBJECT_FLAGS: u32 = SF_FIRMLINK | SF_DATALESS;

/// Explicit trust from the owner of an independently provisioned directory.
///
/// The grant conveys a caller attestation. The adapter checks directory mode,
/// ownership, ACL, filesystem and identities. The read capability either owns a
/// shared advisory lock or borrows a separately authorized exclusive lock.
#[derive(Debug)]
pub struct ManagedReadGrant(());

impl ManagedReadGrant {
	/// Record deliberate authorization by the trusted owner of a managed root.
	///
	/// Issue this grant only in a trusted, local mount namespace for the exact,
	/// independently provisioned, materialized directory outside File Provider.
	/// No outside principal may already hold or receive a handle to that root
	/// or to any selected file during the capability's lifetime.
	///
	/// Every cooperating actor under the same effective UID must independently
	/// open the directory and hold an exclusive Darwin `flock` before changing
	/// the directory, any names, or any selected files, including through
	/// aliases or previously retained handles. The read capability requires a
	/// held lease throughout use.
	///
	/// Basic metadata admission covers attributes visible to the process and the
	/// selected timestamp, mode, ownership and unnamed-stream profile. The root
	/// owner must establish that this profile suffices for the selected child.
	///
	/// For path admission, every ancestor and its directory entries must be
	/// protected against redirection through the initial open. Resolution
	/// must reliably reach this exact provisioned root without autofs or
	/// another lookup trigger, remote filesystem activity, or File Provider
	/// lookups. Path spelling, permissions and no-follow flags alone cannot
	/// establish those facts.
	#[must_use]
	pub const fn trusted_owner_authorizes_provisioned_root() -> Self {
		Self(())
	}
}

/// A held, explicitly authorized owner-private local APFS directory.
///
/// Concurrent readers may hold independent shared advisory locks on the same
/// directory. The shared lock is released when the capability is dropped.
pub struct ManagedReadRoot {
	directory: File,
	owner: u32,
	identity: DirectoryIdentity,
	lease_process: u32,
}

impl fmt::Debug for ManagedReadRoot {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("ManagedReadRoot")
			.finish_non_exhaustive()
	}
}

impl ManagedReadRoot {
	/// Bind an authorized, held read-only directory descriptor.
	///
	/// The caller supplies a descriptor opened under the grant's restrictions.
	/// The adapter independently reopens the same directory and acquires the
	/// lease on the new close-on-exec descriptor. Use
	/// [Self::open_provisioned_path] to have the adapter resolve an absolute
	/// path with symlink and dataless materialization controls.
	///
	/// # Errors
	///
	/// Refuses an unqualified root, an unavailable advisory lock, missing
	/// permission or ACL evidence, and system or thread policy failures.
	pub fn from_provisioned_directory(
		directory: File,
		_grant: ManagedReadGrant,
	) -> Result<Self, ManagedReadError> {
		with_materialization_disabled(|| {
			let imported = capture_directory(&directory)?;
			let descriptor = fs::openat(&directory, c".", DIRECTORY_OPEN, Mode::empty())?;
			Self::bind_directory(File::from(descriptor), Some(imported))
		})
	}

	/// Walk the explicitly granted absolute root path using held directories.
	///
	/// Opens one directory component at a time without following symlinks
	/// and with dataless materialization disabled on the calling thread.
	/// The [grant contract](ManagedReadGrant::trusted_owner_authorizes_provisioned_root)
	/// requires stable, trusted resolution to the exact independently
	/// provisioned root without mount or lookup triggers.
	///
	/// # Errors
	///
	/// Refuses relative paths, empty or traversal components, symlinks and any
	/// root missing descriptor, ACL, volume, policy or advisory lock evidence.
	pub fn open_provisioned_path(
		path: &Path,
		_grant: ManagedReadGrant,
	) -> Result<Self, ManagedReadError> {
		let relative = provisioned_path_components(path)?;
		with_materialization_disabled(|| {
			Self::bind_directory(open_provisioned_directory(relative)?, None)
		})
	}

	fn bind_directory(
		directory: File,
		imported: Option<DirectoryIdentity>,
	) -> Result<Self, ManagedReadError> {
		let identity = capture_directory(&directory)?;
		if imported.is_some_and(|imported| imported != identity) {
			return Err(ManagedReadError::UnsupportedNamespace);
		}
		let owner = rustix::process::geteuid().as_raw();
		check_directory_authority(&directory, owner, identity)?;
		if !volume::supports_managed_root(directory.as_fd())? {
			return Err(ManagedReadError::UnsupportedNamespace);
		}
		match fs::flock(&directory, FlockOperation::NonBlockingLockShared) {
			Ok(()) => {}
			Err(Errno::AGAIN) => return Err(ManagedReadError::DirectoryBusy),
			Err(error) => return Err(error.into()),
		}
		let root = Self {
			directory,
			owner,
			identity,
			lease_process: process::id(),
		};
		root.read_directory().check_root()?;
		Ok(root)
	}

	/// Select one owner-private, single-link regular file without following links.
	///
	/// The checked name and held root remain bound to the returned read view.
	/// A controlled namespace is required through the pre-open metadata checks
	/// and readable open. Darwin's open flags alone cannot reject substitution
	/// of a special file in an uncontrolled namespace.
	///
	/// # Errors
	///
	/// Fails if the name is missing, the child or root cannot be admitted, any
	/// observation changes, or the required I/O policy cannot be established.
	pub fn open_regular<'root>(
		&'root self,
		name: UnixComponent<'root>,
	) -> Result<ManagedRegularFile<'root>, ManagedReadError> {
		with_materialization_disabled(|| self.read_directory().open_with_policy(name))
	}

	fn read_directory(&self) -> ReadDirectory<'_> {
		ReadDirectory {
			directory: &self.directory,
			owner: self.owner,
			identity: self.identity,
			lease_process: self.lease_process,
		}
	}
}

struct ReadDirectory<'root> {
	directory: &'root File,
	owner: u32,
	identity: DirectoryIdentity,
	lease_process: u32,
}

impl<'root> ReadDirectory<'root> {
	fn check_process(&self) -> Result<(), ManagedReadError> {
		if self.lease_process != process::id() {
			return Err(ManagedReadError::UnsupportedNamespace);
		}
		Ok(())
	}

	fn check_root(&self) -> Result<(), ManagedReadError> {
		self.check_process()?;
		check_directory_authority(self.directory, self.owner, self.identity)
	}

	fn open_with_policy(
		self,
		name: UnixComponent<'root>,
	) -> Result<ManagedRegularFile<'root>, ManagedReadError> {
		self.check_root()?;
		let before = match fs::statat(self.directory, name.as_bytes(), AtFlags::SYMLINK_NOFOLLOW) {
			Ok(stat) => stat,
			Err(Errno::NOENT) => return Err(ManagedReadError::Missing),
			Err(error) => return Err(error.into()),
		};
		if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
			|| before.st_dev != self.identity.device
			|| before.st_uid != self.owner
			|| before.st_nlink != 1
			|| Mode::from_raw_mode(before.st_mode) != FILE_MODE
			|| before.st_flags & UNSUPPORTED_OBJECT_FLAGS != 0
			|| self.named_fsid(name)? != Some(self.identity.physical_fsid)
		{
			return Err(ManagedReadError::UnsupportedChild);
		}
		let length =
			u64::try_from(before.st_size).map_err(|_| ManagedReadError::UnsupportedChild)?;
		let descriptor = fs::openat(
			self.directory,
			name.as_bytes(),
			OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
			Mode::empty(),
		)?;
		let descriptor = File::from(descriptor);
		let initial = fs::fstat(&descriptor)?;
		if !file::same_observation(&initial, &before) {
			return Err(ManagedReadError::SourceChanged);
		}
		let file = ManagedRegularFile::new(self, name, descriptor, initial, length);
		file.check_file()?;
		Ok(file)
	}

	fn named_fsid(
		&self,
		name: UnixComponent<'_>,
	) -> Result<Option<PhysicalFsid>, ManagedReadError> {
		match PhysicalFsid::named(self.directory.as_fd(), name) {
			Ok(fsid) => Ok(fsid),
			Err(error) if error.kind() == io::ErrorKind::NotFound => {
				Err(ManagedReadError::SourceChanged)
			}
			Err(error) => Err(error.into()),
		}
	}
}

impl Drop for ManagedReadRoot {
	fn drop(&mut self) {
		// A fork can briefly retain the open description even with CLOEXEC.
		if self.lease_process == process::id() {
			let _ = fs::flock(&self.directory, FlockOperation::Unlock);
		}
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
	device: libc::dev_t,
	inode: libc::ino_t,
	generation: u32,
	physical_fsid: PhysicalFsid,
	birth: ManagedTimestamp,
}

impl DirectoryIdentity {
	fn from_stat(stat: &Stat, physical_fsid: PhysicalFsid) -> Result<Self, ManagedReadError> {
		let observation = ManagedObjectIdentity::from_stat(stat, physical_fsid)
			.ok_or(ManagedReadError::UnsupportedNamespace)?;
		Ok(Self {
			device: stat.st_dev,
			inode: stat.st_ino,
			generation: stat.st_gen,
			physical_fsid,
			birth: observation.birth(),
		})
	}

	fn matches_stat(self, stat: &Stat) -> bool {
		Self::from_stat(stat, self.physical_fsid).is_ok_and(|identity| self == identity)
	}

	fn observe(self, directory: &File) -> Result<ManagedObjectIdentity, ManagedReadError> {
		let stat = fs::fstat(directory)?;
		if !self.matches_stat(&stat) {
			return Err(ManagedReadError::UnsupportedNamespace);
		}
		ManagedObjectIdentity::from_stat(&stat, self.physical_fsid)
			.ok_or(ManagedReadError::UnsupportedNamespace)
	}
}

fn check_directory_authority(
	directory: &File,
	owner: u32,
	identity: DirectoryIdentity,
) -> Result<(), ManagedReadError> {
	let stat = fs::fstat(directory)?;
	let mount = fs::fstatfs(directory)?;
	if owner == 0
		|| rustix::process::geteuid().as_raw() != owner
		|| stat.st_uid != owner
		|| !identity.matches_stat(&stat)
		|| FileType::from_raw_mode(stat.st_mode) != FileType::Directory
		|| Mode::from_raw_mode(stat.st_mode) != DIRECTORY_MODE
		|| stat.st_flags & UNSUPPORTED_OBJECT_FLAGS != 0
		|| !mount.f_fstypename.starts_with(&APFS_NAME)
		|| mount.f_flags & libc::MNT_LOCAL as u32 == 0
		|| mount.f_flags & libc::MNT_IGNORE_OWNERSHIP as u32 != 0
		|| PhysicalFsid::held(directory.as_fd())? != Some(identity.physical_fsid)
		|| !acl::has_explicit_empty_acl(directory.as_fd())?
	{
		return Err(ManagedReadError::UnsupportedNamespace);
	}
	Ok(())
}

fn provisioned_path_components(path: &Path) -> Result<&[u8], ManagedReadError> {
	let raw = path.as_os_str().as_bytes();
	let Some(relative) = raw.strip_prefix(b"/") else {
		return Err(ManagedReadError::UnsupportedNamespace);
	};
	if raw.len() >= libc::PATH_MAX as usize
		|| relative
			.split(|&byte| byte == b'/')
			.any(|name| UnixComponent::new(name).is_err())
	{
		return Err(ManagedReadError::UnsupportedNamespace);
	}
	Ok(relative)
}

// The caller holds the dataless materialization scope through path resolution.
fn open_provisioned_directory(relative: &[u8]) -> Result<File, ManagedReadError> {
	let mut directory = fs::open(c"/", DIRECTORY_OPEN, Mode::empty())?;
	for child in relative.split(|&byte| byte == b'/') {
		directory = fs::openat(&directory, child, DIRECTORY_OPEN, Mode::empty())?;
	}
	Ok(directory.into())
}

fn capture_directory(directory: &File) -> Result<DirectoryIdentity, ManagedReadError> {
	let flags = fs::fcntl_getfl(directory)?;
	let stat = fs::fstat(directory)?;
	if flags.intersection(OFlags::ACCMODE) != OFlags::RDONLY
		|| flags.contains(EVENT_ONLY)
		|| FileType::from_raw_mode(stat.st_mode) != FileType::Directory
		|| stat.st_flags & UNSUPPORTED_OBJECT_FLAGS != 0
	{
		return Err(ManagedReadError::UnsupportedNamespace);
	}
	let physical_fsid =
		PhysicalFsid::held(directory.as_fd())?.ok_or(ManagedReadError::UnsupportedNamespace)?;
	DirectoryIdentity::from_stat(&stat, physical_fsid)
}
