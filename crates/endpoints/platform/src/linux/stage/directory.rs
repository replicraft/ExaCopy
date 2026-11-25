use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;

use exacopy_endpoint::UnixComponent;
use exacopy_model::CopyBinding;
use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags};
use rustix::process::geteuid;

use super::super::handle::{FileIdentity, file_identity, mount_id};
use super::{StageError, WriteStage};

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
	.union(OFlags::DIRECTORY)
	.union(OFlags::CLOEXEC)
	.union(OFlags::NOFOLLOW);
const DIRECTORY_MODE: Mode = Mode::RUSR.union(Mode::WUSR).union(Mode::XUSR);

pub(super) const CHILD_RESOLVE: ResolveFlags = ResolveFlags::BENEATH
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
	pub(super) directory: File,
	pub(super) mount: u64,
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
		Ok(Self { directory, mount })
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
		check_managed_parent(&self.directory)?;
		fs::mkdirat(&self.directory, component(name), DIRECTORY_MODE)
			.map_err(StageError::on_create)?;
		let directory = fs::openat2(
			&self.directory,
			component(name),
			DIRECTORY_FLAGS,
			Mode::empty(),
			CHILD_RESOLVE,
		)?
		.into();
		check_private_directory(&directory)?;
		if mount_id(&directory)? != self.mount {
			return Err(StageError::IdentityChanged);
		}
		let identity = file_identity(&directory)?;

		Ok(StageDirectory {
			root: self,
			directory,
			name: StageName::from(name),
			identity,
		})
	}
}

/// A newly created, held private staging directory on the destination mount.
///
/// Paths and descriptors are kept private. Code running with the same effective
/// user or elevated privileges is trusted by this interface.
pub struct StageDirectory<'root> {
	pub(super) root: &'root DestinationRoot,
	pub(super) directory: File,
	name: StageName,
	identity: FileIdentity,
}

impl StageDirectory<'_> {
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
		self.check_current()?;
		WriteStage::create(self, name, target, binding)
	}

	pub(super) fn check_current(&self) -> Result<(), StageError> {
		check_managed_parent(&self.root.directory)?;
		check_private_directory(&self.directory)?;
		let named = fs::openat2(
			&self.root.directory,
			self.name.as_os_str(),
			OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
			Mode::empty(),
			CHILD_RESOLVE,
		)?;
		if file_identity(&named)? != self.identity || mount_id(&named)? != self.root.mount {
			return Err(StageError::IdentityChanged);
		}
		Ok(())
	}
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

pub(super) fn component(name: UnixComponent<'_>) -> &OsStr {
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
		Self(component(name).into())
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
