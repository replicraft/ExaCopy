use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;

use exacopy_endpoint::UnixComponent;
use exacopy_model::CopyBinding;
use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags};
use rustix::process::geteuid;

use super::super::handle::{FileIdentity, file_identity, mount_id};
use super::super::job::{JobDirectory, STAGE};
use super::super::recovery::RecoveryJob;
use super::file::create_private_file;
use super::{StageError, WriteStage};

#[cfg(test)]
mod tests;

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
	.union(OFlags::DIRECTORY)
	.union(OFlags::CLOEXEC)
	.union(OFlags::NOFOLLOW);
const DIRECTORY_MODE: Mode = Mode::RUSR.union(Mode::WUSR).union(Mode::XUSR);

pub(in crate::linux) const CHILD_RESOLVE: ResolveFlags = ResolveFlags::BENEATH
	.union(ResolveFlags::NO_MAGICLINKS)
	.union(ResolveFlags::NO_SYMLINKS)
	.union(ResolveFlags::NO_XDEV);

/// A held, managed destination directory for one-component relative operations.
///
/// Its owner is the effective user. Other principals may create entries only in a
/// sticky directory, where they cannot move entries owned by the effective user
/// out from under a newly created private stage. The contract assumes that Linux
/// enforces the applicable ownership, ACL and sticky-bit rules.
pub struct DestinationRoot {
	pub(in crate::linux) directory: File,
	pub(in crate::linux) mount: u64,
	identity: FileIdentity,
}

impl DestinationRoot {
	/// Takes an authorized directory handle and opens it for directory barriers.
	///
	/// # Errors
	///
	/// Rejects non-directories and directories outside the managed-parent contract.
	/// Also returns an error if opening or identifying the held directory fails.
	pub fn from_directory(directory: File) -> Result<Self, StageError> {
		check_managed_parent(&directory)?;
		let directory: File = fs::openat2(
			&directory,
			c".",
			DIRECTORY_FLAGS,
			Mode::empty(),
			CHILD_RESOLVE,
		)?
		.into();
		let mount = mount_id(&directory)?;
		let identity = file_identity(&directory)?;
		Ok(Self {
			directory,
			mount,
			identity,
		})
	}

	/// Returns the identity of the held destination directory.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.identity
	}

	/// Requests a full barrier on the held destination directory.
	///
	/// # Errors
	///
	/// A failed barrier prevents any dependent publication attempt.
	pub fn sync_directory(&self) -> Result<(), StageError> {
		self.sync_directory_admitted(|| Ok(()))
	}

	/// Checks the held parent and admits its barrier immediately before fsync.
	///
	/// # Errors
	/// Refuses an unsafe parent, failed admission or failed barrier.
	pub fn sync_directory_admitted<G>(
		&self,
		enter: impl FnOnce() -> std::io::Result<G>,
	) -> Result<(), StageError> {
		check_managed_parent(&self.directory)?;
		sync_directory_admitted(&self.directory, enter)
	}

	/// Exclusively creates and holds an owner-private staging directory.
	///
	/// The name is caller-selected and never adopted if it already exists.
	///
	/// # Errors
	///
	/// Returns an error for a name collision, an unsafe directory, or a failed
	/// syscall. If creation succeeded before a later error, the new entry remains
	/// for reconciliation.
	pub fn create_stage_directory(
		&self,
		name: UnixComponent<'_>,
	) -> Result<StageDirectory<'_>, StageError> {
		self.check_current()?;
		StageDirectory::create(self, None, component(name))
	}

	pub(in crate::linux) fn check_current(&self) -> Result<(), StageError> {
		check_managed_parent(&self.directory)
	}
}

/// A held private staging directory on the destination mount.
///
/// Paths and descriptors are kept private. Code running with the same effective
/// user or elevated privileges is trusted by this interface.
pub struct StageDirectory<'root> {
	pub(super) root: &'root DestinationRoot,
	pub(super) directory: File,
	name: StageName,
	parent: StageParent<'root>,
	identity: FileIdentity,
}

enum StageParent<'root> {
	Root,
	CopyJob(&'root JobDirectory<'root>),
	RecoveryJob(&'root RecoveryJob<'root>),
}

impl<'root> StageDirectory<'root> {
	pub(in crate::linux) fn create(
		root: &'root DestinationRoot,
		job: Option<&'root JobDirectory<'root>>,
		name: &OsStr,
	) -> Result<Self, StageError> {
		Self::create_admitted(root, job, name, || Ok(()))
	}

	pub(in crate::linux) fn create_admitted<G>(
		root: &'root DestinationRoot,
		job: Option<&'root JobDirectory<'root>>,
		name: &OsStr,
		enter: impl FnOnce() -> std::io::Result<G>,
	) -> Result<Self, StageError> {
		let parent = job.map_or(&root.directory, JobDirectory::directory);
		let (directory, identity) =
			create_private_directory_admitted(parent, name, root.mount, enter)?;
		Ok(Self {
			root,
			directory,
			name: StageName(name.into()),
			parent: job.map_or(StageParent::Root, StageParent::CopyJob),
			identity,
		})
	}

	pub(in crate::linux) fn for_recovery(
		root: &'root DestinationRoot,
		job: &'root RecoveryJob<'root>,
		directory: File,
		identity: FileIdentity,
	) -> Self {
		Self {
			root,
			directory,
			name: OsStr::new(STAGE).into(),
			parent: StageParent::RecoveryJob(job),
			identity,
		}
	}

	/// Returns the identity of the held private staging directory.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.identity
	}

	/// Requests a full barrier on the checked private staging directory.
	///
	/// # Errors
	///
	/// Fails if the held directory became unsafe or detached, or if the
	/// directory barrier fails. A failed barrier prevents dependent effects.
	pub fn sync_directory(&self) -> Result<(), StageError> {
		self.sync_directory_admitted(|| Ok(()))
	}

	/// Checks the private staging directory and admits its barrier before fsync.
	///
	/// # Errors
	/// Refuses a changed directory, failed admission or failed barrier.
	pub fn sync_directory_admitted<G>(
		&self,
		enter: impl FnOnce() -> std::io::Result<G>,
	) -> Result<(), StageError> {
		self.check_current()?;
		sync_directory_admitted(&self.directory, enter)
	}

	/// Exclusively creates a private file for application-owned transaction records.
	///
	/// The returned read/write descriptor is limited to the newly created file
	/// inside this private staging directory. The record writer owns its format,
	/// file barrier, and the response to an uncertain write or barrier.
	///
	/// # Errors
	///
	/// Rejects collisions, unsafe or detached directories, and syscall failures.
	/// If creation preceded a later error, the new entry remains in place.
	pub fn create_record(&self, name: UnixComponent<'_>) -> Result<File, StageError> {
		self.check_current()?;
		let (file, _) = create_private_file(
			&self.directory,
			self.root.mount,
			component(name),
			OFlags::RDWR,
		)?;
		Ok(file)
	}

	/// Exclusively creates a new, owner-private regular file for this binding and target.
	///
	/// The target is fixed here for the lifetime of the stage.
	///
	/// # Errors
	///
	/// Returns an error for a name collision, changed stage directory, unsafe
	/// created file, or failed syscall. The adapter retains entries on failure.
	pub fn create_file(
		&self,
		name: UnixComponent<'_>,
		target: UnixComponent<'_>,
		binding: CopyBinding,
	) -> Result<WriteStage<'_>, StageError> {
		self.create_file_admitted(name, target, binding, || Ok(()))
	}

	pub(in crate::linux) fn create_file_admitted<G>(
		&self,
		name: UnixComponent<'_>,
		target: UnixComponent<'_>,
		binding: CopyBinding,
		enter: impl FnOnce() -> std::io::Result<G>,
	) -> Result<WriteStage<'_>, StageError> {
		self.check_current()?;
		WriteStage::create_admitted(self, name, target, binding, enter)
	}

	pub(super) fn check_current(&self) -> Result<(), StageError> {
		let parent = match self.parent {
			StageParent::Root => {
				self.root.check_current()?;
				&self.root.directory
			}
			StageParent::CopyJob(job) => {
				job.check_current()?;
				job.directory()
			}
			StageParent::RecoveryJob(job) => job.directory_for_stage()?,
		};
		check_private_child(
			parent,
			&self.directory,
			self.name.as_os_str(),
			self.identity,
			self.root.mount,
		)
	}
}

pub(in crate::linux) fn create_private_directory(
	parent: &File,
	name: &OsStr,
	mount: u64,
) -> Result<(File, FileIdentity), StageError> {
	create_private_directory_admitted(parent, name, mount, || Ok(()))
}

pub(in crate::linux) fn create_private_directory_admitted<G>(
	parent: &File,
	name: &OsStr,
	mount: u64,
	enter: impl FnOnce() -> std::io::Result<G>,
) -> Result<(File, FileIdentity), StageError> {
	create_private_directory_observed(parent, name, mount, enter)
		.map_err(DirectoryCreateFailure::into_stage_error)
}

pub(in crate::linux) enum DirectoryCreateFailure {
	Refused(StageError),
	Syscall(rustix::io::Errno),
	Created(StageError),
}

impl DirectoryCreateFailure {
	fn into_stage_error(self) -> StageError {
		match self {
			Self::Refused(cause) | Self::Created(cause) => cause,
			Self::Syscall(cause) => StageError::on_create(cause),
		}
	}
}

pub(in crate::linux) fn create_private_directory_observed<G>(
	parent: &File,
	name: &OsStr,
	mount: u64,
	enter: impl FnOnce() -> std::io::Result<G>,
) -> Result<(File, FileIdentity), DirectoryCreateFailure> {
	let guard =
		enter().map_err(|cause| DirectoryCreateFailure::Refused(StageError::Admission(cause)))?;
	let created = fs::mkdirat(parent, name, DIRECTORY_MODE);
	drop(guard);
	created.map_err(DirectoryCreateFailure::Syscall)?;
	observe_created_directory(parent, name, mount).map_err(DirectoryCreateFailure::Created)
}

fn observe_created_directory(
	parent: &File,
	name: &OsStr,
	mount: u64,
) -> Result<(File, FileIdentity), StageError> {
	let directory =
		fs::openat2(parent, name, DIRECTORY_FLAGS, Mode::empty(), CHILD_RESOLVE)?.into();
	check_private_directory(&directory)?;
	if mount_id(&directory)? != mount {
		return Err(StageError::IdentityChanged);
	}
	let identity = file_identity(&directory)?;
	Ok((directory, identity))
}

pub(in crate::linux) fn check_private_child(
	parent: &File,
	directory: &File,
	name: &OsStr,
	identity: FileIdentity,
	mount: u64,
) -> Result<(), StageError> {
	check_private_directory(directory)?;
	let named = fs::openat2(
		parent,
		name,
		OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
		Mode::empty(),
		CHILD_RESOLVE,
	)?;
	if file_identity(&named)? != identity || mount_id(&named)? != mount {
		return Err(StageError::IdentityChanged);
	}
	Ok(())
}

pub(in crate::linux) fn sync_directory(directory: &File) -> Result<(), StageError> {
	sync_directory_admitted(directory, || Ok(()))
}

pub(in crate::linux) fn sync_directory_admitted<G>(
	directory: &File,
	enter: impl FnOnce() -> std::io::Result<G>,
) -> Result<(), StageError> {
	let _guard = enter().map_err(StageError::Admission)?;
	fs::fsync(directory).map_err(|source| StageError::DirectoryBarrierFailed(source.into()))
}

fn check_managed_parent(directory: &File) -> Result<(), StageError> {
	let stat = fs::fstat(directory)?;
	let mode = Mode::from_raw_mode(stat.st_mode);
	// The POSIX ACL mask, if present, is represented by the group mode bits.
	let other_write = mode.intersects(Mode::WGRP | Mode::WOTH);
	if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
		|| stat.st_uid != geteuid().as_raw()
		|| (other_write && !mode.contains(Mode::SVTX))
	{
		return Err(StageError::UnsafeDirectory);
	}
	Ok(())
}

fn check_private_directory(directory: &File) -> Result<(), StageError> {
	let stat = fs::fstat(directory)?;
	if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
		|| stat.st_uid != geteuid().as_raw()
		|| Mode::from_raw_mode(stat.st_mode) != DIRECTORY_MODE
	{
		return Err(StageError::UnsafeDirectory);
	}
	Ok(())
}

pub(in crate::linux) fn component(name: UnixComponent<'_>) -> &OsStr {
	OsStr::from_bytes(name.as_bytes())
}

pub(super) struct StageName(Box<OsStr>);

impl StageName {
	pub(super) fn as_os_str(&self) -> &OsStr {
		&self.0
	}
}

impl From<UnixComponent<'_>> for StageName {
	fn from(name: UnixComponent<'_>) -> Self {
		Self::from(component(name))
	}
}

impl From<&OsStr> for StageName {
	fn from(name: &OsStr) -> Self {
		Self(name.into())
	}
}

impl fmt::Debug for DestinationRoot {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("DestinationRoot")
			.finish_non_exhaustive()
	}
}

impl fmt::Debug for StageDirectory<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("StageDirectory")
			.field("identity", &self.identity)
			.finish_non_exhaustive()
	}
}
