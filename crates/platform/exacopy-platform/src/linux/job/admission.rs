use std::{ffi::OsStr, fmt, fs::File, io, os::unix::fs::FileExt as _};

use exacopy_endpoint::UnixComponent;
use rustix::fs::{FlockOperation, OFlags, Stat};
use rustix::io::Errno;

use super::super::handle::FileIdentity;
use super::super::stage::{
	DirectoryCreateFailure, component, create_private_directory_admitted,
	create_private_directory_observed, create_private_file_admitted, sync_directory_admitted,
	write_admitted,
};
use super::{
	DestinationRoot, FIRST_SEGMENT, FreshJournalNames, JOURNAL, JobDirectory, JournalDirectory,
	LinuxJournalSegment, OWNER, RecordDirectory, STAGE, StageDirectory, StageError, TargetStatus,
	try_lock_job,
};

/// Why a requested private job directory could not be handed to the caller.
#[derive(Debug)]
#[non_exhaustive]
pub enum JobDirectoryCreationError {
	/// The request made no new job directory at the selected name.
	NotCreated(StageError),
	/// The kernel returned a failure without establishing the namespace outcome.
	OutcomeUncertain(StageError),
	/// The kernel acknowledged creation, but the new directory was not verified or locked.
	CreatedUnconfirmed(StageError),
}

impl JobDirectoryCreationError {
	pub(super) fn into_stage_error(self) -> StageError {
		match self {
			Self::NotCreated(cause)
			| Self::OutcomeUncertain(cause)
			| Self::CreatedUnconfirmed(cause) => cause,
		}
	}
}

impl fmt::Display for JobDirectoryCreationError {
	fn fmt(&self, display: &mut fmt::Formatter<'_>) -> fmt::Result {
		let (context, cause) = match self {
			Self::NotCreated(cause) => ("job directory was not created", cause),
			Self::OutcomeUncertain(cause) => ("job directory creation is uncertain", cause),
			Self::CreatedUnconfirmed(cause) => {
				("created job directory could not be confirmed", cause)
			}
		};
		write!(display, "{context}: {cause}")
	}
}

impl std::error::Error for JobDirectoryCreationError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::NotCreated(cause)
			| Self::OutcomeUncertain(cause)
			| Self::CreatedUnconfirmed(cause) => Some(cause),
		}
	}
}

impl DestinationRoot {
	/// Checks the destination and enters authority immediately before creating a job.
	///
	/// # Errors
	/// Distinguishes refusal, uncertain creation, and a created directory that could
	/// not be verified or locked. No failure authorizes taking over the selected name.
	pub fn create_job_directory_admitted<G>(
		&self,
		selected: UnixComponent<'_>,
		enter: impl FnOnce() -> io::Result<G>,
	) -> Result<JobDirectory<'_>, JobDirectoryCreationError> {
		use JobDirectoryCreationError as Failure;
		self.check_current().map_err(Failure::NotCreated)?;
		let name = component(selected);
		let (directory, identity) =
			create_private_directory_observed(&self.directory, name, self.mount, enter)
				.map_err(|failure| self.job_creation_failure(selected, failure))?;
		try_lock_job(&directory, FlockOperation::NonBlockingLockExclusive)
			.map_err(Failure::CreatedUnconfirmed)?;
		Ok(JobDirectory {
			root: self,
			directory,
			name: name.into(),
			identity,
		})
	}

	fn job_creation_failure(
		&self,
		selected: UnixComponent<'_>,
		failure: DirectoryCreateFailure,
	) -> JobDirectoryCreationError {
		use JobDirectoryCreationError as Failure;
		match failure {
			DirectoryCreateFailure::Refused(cause) => Failure::NotCreated(cause),
			DirectoryCreateFailure::Created(cause) => Failure::CreatedUnconfirmed(cause),
			DirectoryCreateFailure::Syscall(Errno::EXIST) => {
				Failure::NotCreated(StageError::AlreadyExists)
			}
			DirectoryCreateFailure::Syscall(cause @ (Errno::NOSPC | Errno::DQUOT))
				if self
					.target_status(selected)
					.is_ok_and(|status| status == TargetStatus::Absent) =>
			{
				Failure::NotCreated(cause.into())
			}
			DirectoryCreateFailure::Syscall(
				cause @ (Errno::ACCESS
				| Errno::BADF
				| Errno::FAULT
				| Errno::INVAL
				| Errno::LOOP
				| Errno::MLINK
				| Errno::NAMETOOLONG
				| Errno::NOENT
				| Errno::NOTDIR
				| Errno::OVERFLOW
				| Errno::PERM
				| Errno::ROFS),
			) => Failure::NotCreated(cause.into()),
			DirectoryCreateFailure::Syscall(cause) => Failure::OutcomeUncertain(cause.into()),
		}
	}
}

impl JobDirectory<'_> {
	/// Creates and writes the fixed owner record with authority for each effect.
	///
	/// # Errors
	/// Refuses changed names, failed admission or I/O and preserves any private entry.
	pub fn write_owner_record_admitted<G>(
		&self,
		bytes: &[u8],
		enter: impl Fn() -> io::Result<G>,
	) -> Result<(), StageError> {
		self.check_current()?;
		let (file, _) = create_private_file_admitted(
			&self.directory,
			self.root.mount,
			OsStr::new(OWNER),
			OFlags::RDWR,
			&enter,
		)?;
		write_admitted(0, bytes, &enter, |position, remaining| {
			file.write_at(remaining, position)
		})?;
		let _guard = enter().map_err(StageError::Admission)?;
		file.sync_all().map_err(StageError::BarrierFailed)
	}

	/// Checks the private job and admits its stage-directory creation.
	///
	/// # Errors
	/// Refuses a changed job, failed admission or failed native creation.
	pub fn create_stage_directory_admitted<G>(
		&self,
		enter: impl FnOnce() -> io::Result<G>,
	) -> Result<StageDirectory<'_>, StageError> {
		self.check_current()?;
		StageDirectory::create_admitted(self.root, Some(self), OsStr::new(STAGE), enter)
	}

	/// Checks the private job and admits its journal-directory creation.
	///
	/// # Errors
	/// Refuses a changed job, failed admission or failed native creation.
	pub fn create_journal_directory_admitted<G>(
		&self,
		enter: impl FnOnce() -> io::Result<G>,
	) -> Result<JournalDirectory<'_>, StageError> {
		self.create_record_directory_admitted(JOURNAL, enter)
			.map(JournalDirectory)
	}

	pub(super) fn create_record_directory_admitted<G>(
		&self,
		name: &'static str,
		enter: impl FnOnce() -> io::Result<G>,
	) -> Result<RecordDirectory<'_>, StageError> {
		self.check_current()?;
		let (directory, identity) = create_private_directory_admitted(
			&self.directory,
			OsStr::new(name),
			self.root.mount,
			enter,
		)?;
		Ok(RecordDirectory {
			job: self,
			directory,
			identity,
			name,
		})
	}

	/// Checks the private job and enters authority immediately before fsync.
	///
	/// # Errors
	/// Refuses a changed job, failed admission or failed native barrier.
	pub fn sync_directory_admitted<G>(
		&self,
		enter: impl FnOnce() -> io::Result<G>,
	) -> Result<(), StageError> {
		self.check_current()?;
		sync_directory_admitted(&self.directory, enter)
	}
}

impl JournalDirectory<'_> {
	/// Checks the held journal and admits exclusive creation of the first segment.
	///
	/// # Errors
	/// Refuses a changed journal, failed admission or failed native creation.
	pub fn create_first_segment_admitted<G>(
		&self,
		enter: impl FnOnce() -> io::Result<G>,
	) -> Result<LinuxJournalSegment<'static>, StageError> {
		let names = FreshJournalNames::hold(&self.0)?;
		let (file, stat) = self.0.create_file_admitted(FIRST_SEGMENT, enter)?;
		Ok(LinuxJournalSegment::fresh(
			file,
			names,
			FileIdentity::from_stat(&stat),
		))
	}

	/// Checks the held journal and enters authority immediately before fsync.
	///
	/// # Errors
	/// Refuses a changed journal, failed admission or failed native barrier.
	pub fn sync_directory_admitted<G>(
		&self,
		enter: impl FnOnce() -> io::Result<G>,
	) -> Result<(), StageError> {
		self.0.check_current()?;
		sync_directory_admitted(&self.0.directory, enter)
	}
}

impl RecordDirectory<'_> {
	pub(super) fn create_file_admitted<G>(
		&self,
		name: &str,
		enter: impl FnOnce() -> io::Result<G>,
	) -> Result<(File, Stat), StageError> {
		self.check_current()?;
		create_private_file_admitted(
			&self.directory,
			self.job.root.mount,
			OsStr::new(name),
			OFlags::RDWR,
			enter,
		)
	}
}

#[cfg(test)]
#[path = "../../../tests/unit/job_admission.rs"]
mod setup_tests;

#[cfg(test)]
mod tests {
	use std::fs;
	use std::os::unix::fs::PermissionsExt as _;

	use super::*;
	use crate::scratch::Scratch;

	#[test]
	fn unavailable_parent_and_incumbent_refuse_before_owning_a_job() {
		let scratch = Scratch::new();
		let path = scratch.path("root");
		fs::create_dir(&path).unwrap();
		fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
		let root = DestinationRoot::from_directory(File::open(&path).unwrap()).unwrap();
		let selected = UnixComponent::new(b"job").unwrap();

		fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
		let refused = root.create_job_directory_admitted(selected, || -> io::Result<()> {
			panic!("unsafe root reached the native effect gate")
		});
		assert!(matches!(
			refused,
			Err(JobDirectoryCreationError::NotCreated(
				StageError::UnsafeDirectory
			))
		));
		assert!(!path.join("job").exists());

		fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
		fs::write(path.join("job"), b"incumbent").unwrap();
		let refused = root.create_job_directory_admitted(selected, || Ok(()));
		assert!(matches!(
			refused,
			Err(JobDirectoryCreationError::NotCreated(
				StageError::AlreadyExists
			))
		));
		assert_eq!(fs::read(path.join("job")).unwrap(), b"incumbent");
	}

	#[test]
	fn capacity_failure_does_not_claim_custody_and_unknown_syscalls_stay_uncertain() {
		use JobDirectoryCreationError as Failure;

		let scratch = Scratch::new();
		let root = DestinationRoot::from_directory(scratch.open()).unwrap();
		let selected = UnixComponent::new(b"job").unwrap();
		let fullness = || DirectoryCreateFailure::Syscall(Errno::NOSPC);
		assert!(matches!(
			root.job_creation_failure(selected, fullness()),
			Failure::NotCreated(StageError::System(cause)) if cause.raw_os_error() == Some(Errno::NOSPC.raw_os_error())
		));
		assert!(matches!(
			root.job_creation_failure(selected, DirectoryCreateFailure::Syscall(Errno::IO)),
			Failure::OutcomeUncertain(StageError::System(cause)) if cause.raw_os_error() == Some(Errno::IO.raw_os_error())
		));
		fs::write(scratch.path("job"), b"external name").unwrap();
		assert!(matches!(
			root.job_creation_failure(selected, fullness()),
			Failure::OutcomeUncertain(StageError::System(cause)) if cause.raw_os_error() == Some(Errno::NOSPC.raw_os_error())
		));
		assert!(matches!(
			root.job_creation_failure(
				selected,
				DirectoryCreateFailure::Created(StageError::JobBusy)
			),
			Failure::CreatedUnconfirmed(StageError::JobBusy)
		));
		assert_eq!(fs::read(scratch.path("job")).unwrap(), b"external name");
	}
}
