//! Private job creation and read-only inspection within a provisioned APFS container.

use std::fmt;
use std::fs::File;
use std::os::fd::AsFd as _;

use exacopy_endpoint::UnixComponent;
use rustix::fs::{self, FileType, Mode, Stat};

use super::super::super::{
	DIRECTORY_MODE, DIRECTORY_OPEN, ManagedObjectIdentity, acl, with_materialization_disabled,
};
use super::{DirectoryIdentity, DirectoryLease, StageDirectory, StageError};

mod error;
mod identity;
mod receipt;
mod record;
mod recovery;

#[cfg(test)]
mod tests;

pub use error::{JobArtifact, JobError, JobStep};
pub use identity::JobName;
pub use recovery::{
	RecoveryError, RecoveryFileObservation, RecoveryInventory, RecoveryJob, RecoveryName,
	RecoveryRecord, RecoveryStageReader,
};

const JOURNAL: &[u8] = b"journal";
const RECEIPTS: &[u8] = b"receipts";
const STAGE: &[u8] = b"stage";

impl StageDirectory<'_> {
	/// Checks the provisioned private container and observes an empty public target.
	///
	/// Returns the identity of the leased destination root that contains this container.
	/// The raw target is looked up without following symlinks. The observation is
	/// current only under the managed lease contract and authorizes no publication.
	///
	/// # Errors
	/// Refuses a directory inside an existing job, changed authority or identity,
	/// an occupied target, and inconclusive lookups.
	pub fn observe_empty_job_destination(
		&self,
		target: UnixComponent<'_>,
	) -> Result<ManagedObjectIdentity, JobError> {
		if self.job.is_some() {
			return Err(JobError::NestedJob);
		}
		with_materialization_disabled(|| {
			self.check_current()?;
			self.check_target_absent(target)?;
			Ok(self.root.lease.observe_identity()?)
		})
	}

	/// Exclusively creates a job under the already reserved private container.
	///
	/// The caller's managed grant covers the container and all job artifacts it creates.
	/// The grant's no-fork and same-UID lease rules apply from creation through use.
	///
	/// # Errors
	/// Rejects use below an existing job, occupied names, changed namespace evidence,
	/// failed barriers and system errors. An uncertain creation must be reconciled.
	pub fn create_job_directory(&self, name: JobName) -> Result<JobDirectory<'_>, JobError> {
		if self.job.is_some() {
			return Err(JobError::NestedJob);
		}
		let component = name.to_string();
		let native_name = checked_component(component.as_bytes())?;
		let creation = Creation::new(name, JobArtifact::Directory);
		let directory = creation.run(|creation| {
			self.check_current()?;
			let directory = create_directory(&self.lease, native_name, creation, || {
				Ok(self.check_current()?)
			})?;
			Ok(directory)
		})?;
		Ok(JobDirectory {
			container: self,
			name,
			component: component.into_boxed_str(),
			directory,
		})
	}
}

/// A held exclusively created job and its reserved private container.
///
/// Bootstrap operations must be serialized by the coordinator. Any uncertain
/// operation ends bootstrap and leaves the existing job artifacts in place.
pub struct JobDirectory<'container> {
	container: &'container StageDirectory<'container>,
	name: JobName,
	component: Box<str>,
	directory: PrivateDirectory,
}

impl JobDirectory<'_> {
	/// Returns the job's typed private component.
	#[must_use]
	pub const fn name(&self) -> JobName {
		self.name
	}

	/// Returns the job inode observation from exclusive creation.
	#[must_use]
	pub const fn identity(&self) -> ManagedObjectIdentity {
		self.directory.identity
	}

	/// Returns the effective UID checked against the held job directory.
	#[must_use]
	pub const fn owner_uid(&self) -> u32 {
		self.directory.lease.owner
	}

	/// Exclusively creates and synchronizes the fixed `journal/` subdirectory.
	///
	/// # Errors
	/// Refuses collisions, changed identities and failed authority or barrier checks.
	pub fn create_journal_directory(&self) -> Result<JournalDirectory<'_>, JobError> {
		Ok(JournalDirectory {
			job: self,
			directory: self.create_child(JobArtifact::Journal, JOURNAL)?,
		})
	}

	/// Exclusively creates and synchronizes the fixed `receipts/` subdirectory.
	///
	/// # Errors
	/// Refuses collisions, changed identities and failed authority or barrier checks.
	pub fn create_receipt_directory(&self) -> Result<ReceiptDirectory<'_>, JobError> {
		Ok(ReceiptDirectory {
			job: self,
			directory: self.create_child(JobArtifact::Receipts, RECEIPTS)?,
		})
	}

	/// Exclusively creates the fixed `stage/` subdirectory and its leased staging capability.
	///
	/// # Errors
	/// Refuses collisions, changed identities and failed authority or barrier checks.
	pub fn create_stage_directory(&self) -> Result<StageDirectory<'_>, JobError> {
		let directory = self.create_child(JobArtifact::Stage, STAGE)?;
		Ok(StageDirectory {
			root: self.container.root,
			job: Some(self),
			name: checked_component(STAGE)?,
			lease: directory.lease,
		})
	}

	fn create_child(
		&self,
		artifact: JobArtifact,
		name: &'static [u8],
	) -> Result<PrivateDirectory, JobError> {
		let name = checked_component(name)?;
		Creation::new(self.name, artifact).run(|creation| {
			self.check_current()?;
			create_directory(&self.directory.lease, name, creation, || {
				self.check_current()
			})
		})
	}

	fn check_current(&self) -> Result<(), JobError> {
		self.container.check_current()?;
		let name = checked_component(self.component.as_bytes())?;
		self.directory.check_current(&self.container.lease, name)
	}

	pub(super) fn named_stage_stat(&self, name: UnixComponent<'_>) -> Result<Stat, StageError> {
		self.check_current().map_err(|failure| match failure {
			JobError::Managed(source) => source,
			JobError::System(source) => source.into(),
			_ => StageError::DirectoryChanged,
		})?;
		self.directory.lease.named_stat(name)
	}
}

impl fmt::Debug for JobDirectory<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("JobDirectory")
			.finish_non_exhaustive()
	}
}

/// A held, exclusively created first-segment namespace.
#[derive(Debug)]
pub struct JournalDirectory<'job> {
	job: &'job JobDirectory<'job>,
	directory: PrivateDirectory,
}

/// A held, exclusively created immutable receipt namespace.
#[derive(Debug)]
pub struct ReceiptDirectory<'job> {
	job: &'job JobDirectory<'job>,
	directory: PrivateDirectory,
}

struct PrivateDirectory {
	lease: DirectoryLease,
	identity: ManagedObjectIdentity,
}

impl PrivateDirectory {
	fn check_current(
		&self,
		parent: &DirectoryLease,
		name: UnixComponent<'_>,
	) -> Result<(), JobError> {
		self.lease.check_current()?;
		let named = parent.named_stat(name)?;
		if !self.lease.identity.matches_stat(&named) {
			return Err(JobError::IdentityChanged);
		}
		Ok(())
	}
}

impl fmt::Debug for PrivateDirectory {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("PrivateDirectory")
			.finish_non_exhaustive()
	}
}

fn create_directory(
	parent: &DirectoryLease,
	name: UnixComponent<'_>,
	creation: &mut Creation,
	check_parent: impl Fn() -> Result<(), JobError>,
) -> Result<PrivateDirectory, JobError> {
	creation.create(|| fs::mkdirat(&parent.file, name.as_bytes(), DIRECTORY_MODE))?;
	creation.step = Some(JobStep::Bind);
	let named = parent.named_stat(name)?;
	let expected = DirectoryIdentity::from_stat(&named, parent.identity.physical_fsid)?;
	let file = File::from(fs::openat(
		&parent.file,
		name.as_bytes(),
		DIRECTORY_OPEN,
		Mode::empty(),
	)?);
	if super::capture_directory(&file)? != expected {
		return Err(JobError::IdentityChanged);
	}
	let lease = DirectoryLease::lock(file, parent.owner, expected)?;
	check_parent()?;
	let held = fs::fstat(&lease.file)?;
	let named = parent.named_stat(name)?;
	if !expected.matches_stat(&held)
		|| !expected.matches_stat(&named)
		|| held.st_uid != parent.owner
		|| FileType::from_raw_mode(held.st_mode) != FileType::Directory
		|| Mode::from_raw_mode(held.st_mode) != DIRECTORY_MODE
		|| held.st_flags != 0
		|| !acl::has_no_stage_acl_entries(lease.file.as_fd())?
	{
		return Err(JobError::IdentityChanged);
	}
	let identity = expected.observe(&lease.file)?;
	acl::set_empty_acl_on_fresh_directory(lease.file.as_fd())?;
	let directory = PrivateDirectory { lease, identity };
	directory.check_current(parent, name)?;
	creation.step = Some(JobStep::NamespaceBarrier);
	fs::fsync(&directory.lease.file)?;
	fs::fsync(&parent.file)?;
	creation.step = Some(JobStep::Revalidate);
	check_parent()?;
	directory.check_current(parent, name)?;
	Ok(directory)
}

fn checked_component(bytes: &[u8]) -> Result<UnixComponent<'_>, JobError> {
	UnixComponent::new(bytes).map_err(|_| JobError::IdentityChanged)
}

struct Creation {
	job: JobName,
	artifact: JobArtifact,
	step: Option<JobStep>,
}

impl Creation {
	const fn new(job: JobName, artifact: JobArtifact) -> Self {
		Self {
			job,
			artifact,
			step: None,
		}
	}

	fn run<T>(
		mut self,
		operation: impl FnOnce(&mut Self) -> Result<T, JobError>,
	) -> Result<T, JobError> {
		let result = with_materialization_disabled(|| operation(&mut self));
		match (result, self.step) {
			(Err(source), Some(step)) => Err(JobError::Uncertain {
				job: self.job,
				artifact: self.artifact,
				step,
				source: Box::new(source),
			}),
			(result, _) => result,
		}
	}

	fn create<T>(
		&mut self,
		operation: impl FnOnce() -> Result<T, rustix::io::Errno>,
	) -> Result<T, JobError> {
		self.step = Some(JobStep::Create);
		match operation() {
			Ok(value) => Ok(value),
			Err(rustix::io::Errno::EXIST) => {
				self.step = None;
				Err(JobError::Occupied {
					job: self.job,
					artifact: self.artifact,
				})
			}
			Err(error) => Err(error.into()),
		}
	}
}
