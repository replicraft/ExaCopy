use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::FileExt as _;

use exacopy_endpoint::UnixComponent;
use rustix::fs::{self, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use rustix::process::geteuid;

use super::handle::{FileIdentity, file_identity, mount_id};
use super::job::{FIRST_SEGMENT, JOURNAL, RECEIPT, RECEIPTS, STAGE};
use super::source::{
	ExtendedAttributes, ReadError, SourceObservation, check_logical_eof, reopen_regular_read_only,
	reopen_regular_without_atime, xattrs,
};
use super::stage::{CHILD_RESOLVE, DestinationRoot, StageError, check_private_child, component};

mod artifacts;
mod lease;
mod writer;

pub use lease::RecoveryReadLease;
pub use writer::{
	FreshRecoveryStage, RecoveryReceiptDirectory, RecoveryStageDirectory, RecoveryWriteLease,
	RetainedStage,
};

#[cfg(test)]
mod tests;

impl DestinationRoot {
	/// Opens a private job for read-only inspection under this held destination.
	///
	/// # Errors
	/// Rejects missing jobs, unsafe roots or job directories, and lookup failures.
	pub fn open_recovery_job(
		&self,
		name: UnixComponent<'_>,
	) -> Result<RecoveryJob<'_>, StageError> {
		self.check_current()?;
		let name = component(name);
		let directory = PrivateDirectory::open(&self.directory, name, self.mount)?;
		self.check_current()?;
		let directory = directory.ok_or(Errno::NOENT)?;
		let job = RecoveryJob {
			root: self,
			name: name.into(),
			directory,
		};
		job.recheck()?;
		Ok(job)
	}
}

/// A held owner-private job directory for read-only inspections.
///
/// Its ownership and containment checks apply to the current effective user
/// and trusted Linux mount namespace. Callers establish on-disk record authority.
pub struct RecoveryJob<'root> {
	root: &'root DestinationRoot,
	name: Box<OsStr>,
	directory: PrivateDirectory,
}

impl RecoveryJob<'_> {
	/// Returns the identity of the held job directory.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.directory.identity
	}

	/// Returns the identity of the held destination directory.
	#[must_use]
	pub fn destination_identity(&self) -> FileIdentity {
		self.root.identity()
	}

	/// Rechecks that the job is still bound within a managed destination.
	///
	/// # Errors
	/// Fails if the held root or job became unsafe or the job binding changed.
	pub fn recheck(&self) -> Result<(), StageError> {
		self.root.check_current()?;
		self.directory
			.recheck(&self.root.directory, &self.name, self.root.mount)
	}

	/// Observes a private stage name and a public target name with held read-only handles.
	///
	/// Absence describes the observed namespace. The snapshot can become stale
	/// after return and does not confer authority to publish or remove entries.
	///
	/// # Errors
	/// Fails for unsafe objects or directories, lookup failures, or detected rebinds.
	pub fn inventory(
		&self,
		stage: UnixComponent<'_>,
		target: UnixComponent<'_>,
	) -> Result<RecoveryInventory<'_>, StageError> {
		self.recheck()?;
		let mount = self.root.mount;
		let stage_name = component(stage);
		let target_name = component(target);
		let directory = PrivateDirectory::open(&self.directory.file, OsStr::new(STAGE), mount)?;
		let stage = match &directory {
			Some(directory) => open_regular(&directory.file, stage_name, mount, FilePolicy::Stage)?,
			None => None,
		};
		let target = open_regular(&self.root.directory, target_name, mount, FilePolicy::Target)?;
		let inventory = RecoveryInventory {
			job: self,
			directory,
			stage_name: stage_name.into(),
			target_name: target_name.into(),
			stage,
			target,
		};
		inventory.recheck()?;
		Ok(inventory)
	}
}

impl fmt::Debug for RecoveryJob<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("RecoveryJob")
			.field("identity", &self.identity())
			.finish_non_exhaustive()
	}
}

/// Held regular files and observed absences at the selected stage and target names.
pub struct RecoveryInventory<'job> {
	job: &'job RecoveryJob<'job>,
	directory: Option<PrivateDirectory>,
	stage_name: Box<OsStr>,
	target_name: Box<OsStr>,
	stage: Option<RecoveryFile>,
	target: Option<RecoveryFile>,
}

impl RecoveryInventory<'_> {
	/// Returns a held private stage file, if the stage name was present.
	#[must_use]
	pub fn stage(&self) -> Option<&RecoveryFile> {
		self.stage.as_ref()
	}

	/// Returns a held target file, if the target name was present.
	#[must_use]
	pub fn target(&self) -> Option<&RecoveryFile> {
		self.target.as_ref()
	}

	/// Returns the identity of the held private stage directory, if present.
	#[must_use]
	pub fn stage_directory_identity(&self) -> Option<FileIdentity> {
		self.directory.as_ref().map(|directory| directory.identity)
	}

	/// Rechecks the held namespace bindings, observed absences, and file observations.
	///
	/// # Errors
	/// Fails when a directory or file has changed, an absent name appeared, or
	/// a binding cannot be observed again.
	pub fn recheck(&self) -> Result<(), StageError> {
		self.job.recheck()?;
		let mount = self.job.root.mount;
		let job = &self.job.directory.file;
		let stage_directory = OsStr::new(STAGE);
		if let Some(directory) = &self.directory {
			directory.recheck(job, stage_directory, mount)?;
			recheck_regular(
				&directory.file,
				&self.stage_name,
				mount,
				FilePolicy::Stage,
				self.stage(),
			)?;
			directory.recheck(job, stage_directory, mount)?;
		} else {
			check_absent(job, stage_directory)?;
		}
		recheck_regular(
			&self.job.root.directory,
			&self.target_name,
			mount,
			FilePolicy::Target,
			self.target(),
		)?;
		self.job.recheck()
	}
}

impl fmt::Debug for RecoveryInventory<'_> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("RecoveryInventory")
			.field("stage_directory", &self.stage_directory_identity())
			.field("stage", &self.stage)
			.field("target", &self.target)
			.finish_non_exhaustive()
	}
}

/// A held regular file with read-only rights and a captured Linux observation.
///
/// Owned inodes request Linux no-atime reads. Reading an unowned target can update
/// its access time. The caller bounds decoding and interprets the observations.
pub struct RecoveryFile {
	file: File,
	observation: SourceObservation,
}

impl RecoveryFile {
	/// Returns the identity of the held regular file.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.observation.identity()
	}

	/// Returns the observed length at open.
	#[must_use]
	pub fn len(&self) -> u64 {
		self.observation.len()
	}

	/// Returns whether the observed length at open was zero.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.observation.is_empty()
	}

	/// Returns the held inode's basic identity and metadata captured at open.
	#[must_use]
	pub fn observation(&self) -> SourceObservation {
		self.observation
	}

	/// Rechecks the held inode observation, excluding access time.
	///
	/// # Errors
	/// Fails for detectable inode changes and filesystem errors.
	pub fn recheck_observation(&self) -> Result<(), ReadError> {
		let stat = fs::fstat(&self.file)?;
		self.observation.recheck(SourceObservation::capture(&stat)?)
	}

	/// Checks EOF at the captured length with a bounded positional probe.
	///
	/// # Errors
	/// Reports extra data, an unsupported probe or a read failure.
	pub fn check_logical_eof(&self) -> Result<(), ReadError> {
		check_logical_eof(&self.file, self.len())
	}

	/// Checks for extended attribute names visible to this process.
	///
	/// # Errors
	/// Reports an unreadable or unrepresentable attribute list.
	pub fn extended_attributes(&self) -> Result<ExtendedAttributes, ReadError> {
		xattrs::inspect(&self.file)
	}

	/// Fills a buffer at a given offset without changing the stream cursor.
	///
	/// # Errors
	/// Fails if the range exceeds the captured length or if the read fails.
	pub fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), ReadError> {
		let length = u64::try_from(buffer.len()).map_err(|_| ReadError::RangeOutsideFile)?;
		if offset
			.checked_add(length)
			.is_none_or(|end| end > self.len())
		{
			return Err(ReadError::RangeOutsideFile);
		}
		exacopy_endpoint::read_exact_at(offset, buffer, |position, remaining| {
			self.file.read_at(remaining, position)
		})
		.map_err(ReadError::Io)
	}
}

impl Read for RecoveryFile {
	fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
		self.file.read(bytes)
	}
}

impl fmt::Debug for RecoveryFile {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("RecoveryFile")
			.field("identity", &self.identity())
			.finish_non_exhaustive()
	}
}

struct PrivateDirectory {
	file: File,
	identity: FileIdentity,
}

impl PrivateDirectory {
	fn open(parent: &File, name: &OsStr, mount: u64) -> Result<Option<Self>, StageError> {
		let Some(file) = open_path(parent, name)? else {
			return Ok(None);
		};
		let directory = Self {
			identity: file_identity(&file)?,
			file,
		};
		directory.recheck(parent, name, mount)?;
		Ok(Some(directory))
	}

	fn recheck(&self, parent: &File, name: &OsStr, mount: u64) -> Result<(), StageError> {
		check_private_child(parent, &self.file, name, self.identity, mount)
	}
}

#[derive(Clone, Copy)]
enum FilePolicy {
	Record,
	Stage,
	Target,
}

impl FilePolicy {
	fn check(self, stat: &Stat) -> Result<(), StageError> {
		const RECORD_MODE: Mode = Mode::RUSR.union(Mode::WUSR);
		const SPECIAL_BITS: Mode = Mode::SUID.union(Mode::SGID).union(Mode::SVTX);
		let mode = Mode::from_raw_mode(stat.st_mode);
		let private = stat.st_uid == geteuid().as_raw() && stat.st_nlink == 1;
		let valid = match self {
			Self::Record => private && mode == RECORD_MODE,
			Self::Stage => private && !mode.intersects(SPECIAL_BITS),
			Self::Target => true,
		};
		if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || !valid {
			return Err(StageError::UnsafeFile);
		}
		Ok(())
	}
}

fn open_path(parent: &File, name: &OsStr) -> Result<Option<File>, StageError> {
	match fs::openat2(
		parent,
		name,
		OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
		Mode::empty(),
		CHILD_RESOLVE,
	) {
		Ok(file) => Ok(Some(file.into())),
		Err(Errno::NOENT) => Ok(None),
		Err(source) => Err(source.into()),
	}
}

fn check_absent(parent: &File, name: &OsStr) -> Result<(), StageError> {
	if open_path(parent, name)?.is_some() {
		return Err(StageError::IdentityChanged);
	}
	Ok(())
}

fn open_checked_record(
	parent: &File,
	name: &OsStr,
	mount: u64,
) -> Result<Option<RecoveryFile>, StageError> {
	let file = open_regular(parent, name, mount, FilePolicy::Record)?;
	recheck_regular(parent, name, mount, FilePolicy::Record, file.as_ref())?;
	Ok(file)
}

fn open_regular(
	parent: &File,
	name: &OsStr,
	mount: u64,
	policy: FilePolicy,
) -> Result<Option<RecoveryFile>, StageError> {
	let Some(pinned) = open_path(parent, name)? else {
		return Ok(None);
	};
	let before = fs::fstat(&pinned)?;
	policy.check(&before)?;
	let (file, stat) = if before.st_uid == geteuid().as_raw() {
		reopen_regular_without_atime(&pinned)
	} else {
		reopen_regular_read_only(&pinned)
	}
	.map_err(StageError::ReadBack)?;
	policy.check(&stat)?;
	if mount_id(&pinned)? != mount || mount_id(&file)? != mount {
		return Err(StageError::IdentityChanged);
	}
	let observation = SourceObservation::capture(&before).map_err(StageError::ReadBack)?;
	let opened = SourceObservation::capture(&stat).map_err(StageError::ReadBack)?;
	observation.recheck(opened).map_err(StageError::ReadBack)?;
	Ok(Some(RecoveryFile { file, observation }))
}

fn recheck_regular(
	parent: &File,
	name: &OsStr,
	mount: u64,
	policy: FilePolicy,
	file: Option<&RecoveryFile>,
) -> Result<(), StageError> {
	match (open_path(parent, name)?, file) {
		(None, None) => Ok(()),
		(Some(named), Some(file)) => {
			let stat = fs::fstat(&named)?;
			if FileIdentity::from_stat(&stat) != file.identity() || mount_id(&named)? != mount {
				return Err(StageError::IdentityChanged);
			}
			policy.check(&stat)?;
			let named = SourceObservation::capture(&stat).map_err(StageError::ReadBack)?;
			file.observation
				.recheck(named)
				.map_err(StageError::ReadBack)
		}
		_ => Err(StageError::IdentityChanged),
	}
}
