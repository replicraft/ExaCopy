use std::ffi::OsStr;
use std::fmt;
use std::fs::File;

use exacopy_endpoint::UnixComponent;
use rustix::fs::{self, AtFlags, OFlags};
use rustix::io::Errno;

use super::handle::FileIdentity;
use super::stage::{
	DestinationRoot, StageDirectory, StageError, check_private_child, component,
	create_private_directory, create_private_file, sync_directory,
};

#[cfg(test)]
mod tests;

const STAGE: &str = "stage";
const JOURNAL: &str = "journal";
const OWNER: &str = "owner.cbor";
const FIRST_SEGMENT: &str = "00000000000000000001.exajnl";

/// Advisory observation of a relative publication target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetStatus {
	/// The name was absent when inspected.
	Absent,
	/// An entry of any type occupied the name.
	Occupied,
}

impl DestinationRoot {
	/// Observes one target without following a final symlink.
	///
	/// A missing name does not authorize publication. An exclusive rename
	/// still decides whether a target can be published.
	///
	/// # Errors
	///
	/// Returns an error if the destination scope is unsafe or the name cannot
	/// be inspected.
	pub fn target_status(&self, name: UnixComponent<'_>) -> Result<TargetStatus, StageError> {
		self.check_current()?;
		match fs::statat(&self.directory, component(name), AtFlags::SYMLINK_NOFOLLOW) {
			Ok(_) => Ok(TargetStatus::Occupied),
			Err(Errno::NOENT) => Ok(TargetStatus::Absent),
			Err(error) => Err(error.into()),
		}
	}

	/// Exclusively creates an owner-private job directory below the held destination.
	///
	/// # Errors
	///
	/// Rejects collisions and unsafe roots. A failed check or syscall may leave
	/// a newly created directory in place for reconciliation.
	pub fn create_job_directory(
		&self,
		name: UnixComponent<'_>,
	) -> Result<JobDirectory<'_>, StageError> {
		self.check_current()?;
		let name = component(name);
		let (directory, identity) = create_private_directory(&self.directory, name, self.mount)?;
		Ok(JobDirectory {
			root: self,
			directory,
			name: name.into(),
			identity,
		})
	}
}

/// An exclusively created private job directory rooted in one destination handle.
///
/// The job can create only the fixed owner manifest, stage directory and journal
/// directory through this interface. Each operation rechecks the held job binding.
pub struct JobDirectory<'root> {
	root: &'root DestinationRoot,
	directory: File,
	name: Box<OsStr>,
	identity: FileIdentity,
}

impl JobDirectory<'_> {
	/// Returns the held job directory identity.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.identity
	}

	/// Requests a barrier on the checked job directory.
	///
	/// # Errors
	///
	/// Rejects a changed job binding or a failed directory barrier.
	pub fn sync_directory(&self) -> Result<(), StageError> {
		self.check_current()?;
		sync_directory(&self.directory)
	}

	/// Exclusively creates the private `owner.cbor` record.
	///
	/// # Errors
	///
	/// Rejects a changed job binding, a name collision or a syscall failure.
	/// The record writer owns file barriers and reconciliation.
	pub fn create_owner_record(&self) -> Result<File, StageError> {
		self.check_current()?;
		let (file, _) = create_private_file(
			&self.directory,
			self.root.mount,
			OsStr::new(OWNER),
			OFlags::RDWR,
		)?;
		Ok(file)
	}

	/// Exclusively creates the fixed private `stage/` child.
	///
	/// # Errors
	///
	/// Rejects a changed job binding, a name collision or a syscall failure.
	pub fn create_stage_directory(&self) -> Result<StageDirectory<'_>, StageError> {
		self.check_current()?;
		StageDirectory::create(self.root, Some(self), OsStr::new(STAGE))
	}

	/// Exclusively creates the fixed private `journal/` child.
	///
	/// # Errors
	///
	/// Rejects a changed job binding, a name collision or a syscall failure.
	pub fn create_journal_directory(&self) -> Result<JournalDirectory<'_>, StageError> {
		self.check_current()?;
		let (directory, identity) =
			create_private_directory(&self.directory, OsStr::new(JOURNAL), self.root.mount)?;
		Ok(JournalDirectory {
			job: self,
			directory,
			identity,
		})
	}

	pub(super) fn check_current(&self) -> Result<(), StageError> {
		self.root.check_current()?;
		check_private_child(
			&self.root.directory,
			&self.directory,
			&self.name,
			self.identity,
			self.root.mount,
		)
	}

	pub(super) fn directory(&self) -> &File {
		&self.directory
	}
}

/// An exclusively created journal directory bound to one held private job.
pub struct JournalDirectory<'job> {
	job: &'job JobDirectory<'job>,
	directory: File,
	identity: FileIdentity,
}

impl JournalDirectory<'_> {
	/// Returns the held journal directory identity.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.identity
	}

	/// Requests a barrier on the checked journal directory.
	///
	/// # Errors
	///
	/// Rejects a changed job or journal binding, or a failed directory barrier.
	pub fn sync_directory(&self) -> Result<(), StageError> {
		self.check_current()?;
		sync_directory(&self.directory)
	}

	/// Exclusively creates the private `00000000000000000001.exajnl` segment.
	///
	/// # Errors
	///
	/// Rejects a changed directory binding, a name collision or a syscall failure.
	/// The segment writer owns file barriers and reconciliation.
	pub fn create_first_segment(&self) -> Result<File, StageError> {
		self.check_current()?;
		let (file, _) = create_private_file(
			&self.directory,
			self.job.root.mount,
			OsStr::new(FIRST_SEGMENT),
			OFlags::RDWR,
		)?;
		Ok(file)
	}

	fn check_current(&self) -> Result<(), StageError> {
		self.job.check_current()?;
		check_private_child(
			&self.job.directory,
			&self.directory,
			OsStr::new(JOURNAL),
			self.identity,
			self.job.root.mount,
		)
	}
}

impl fmt::Debug for JobDirectory<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("JobDirectory")
			.field("identity", &self.identity)
			.finish_non_exhaustive()
	}
}

impl fmt::Debug for JournalDirectory<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("JournalDirectory")
			.field("identity", &self.identity)
			.finish_non_exhaustive()
	}
}
