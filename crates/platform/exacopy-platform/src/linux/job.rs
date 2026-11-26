use std::ffi::OsStr;
use std::fmt;
use std::fs::File;

use exacopy_endpoint::UnixComponent;
use rustix::fs::{self, AtFlags, FlockOperation, OFlags};
use rustix::io::Errno;

use super::handle::FileIdentity;
use super::journal_segment::LinuxJournalSegment;
use super::stage::{
	DestinationRoot, StageDirectory, StageError, check_private_child, component,
	create_private_file, sync_directory,
};

mod admission;
pub use admission::JobDirectoryCreationError;
mod capabilities;
mod checkpoint;

pub use checkpoint::CheckpointDirectory;
pub(super) use checkpoint::{CHECKPOINTS, check_page_length, checkpoint_page_name};

#[cfg(test)]
mod tests;

pub(super) const STAGE: &str = "stage";
pub(super) const JOURNAL: &str = "journal";
pub(super) const OWNER: &str = "owner.cbor";
pub(super) const PLAN: &str = "plan.cbor";
pub(super) const FIRST_SEGMENT: &str = "00000000000000000001.exajnl";
pub(super) const RECEIPTS: &str = "receipts";
pub(super) const RECEIPT: &str = "receipt.cbor";

pub use exacopy_endpoint::linux_copy::TargetObservation as TargetStatus;

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
		self.create_job_directory_admitted(name, || Ok(()))
			.map_err(JobDirectoryCreationError::into_stage_error)
	}
}

pub(super) fn try_lock_job(directory: &File, operation: FlockOperation) -> Result<(), StageError> {
	match fs::flock(directory, operation) {
		Ok(()) => Ok(()),
		Err(Errno::WOULDBLOCK) => Err(StageError::JobBusy),
		Err(error) => Err(error.into()),
	}
}

/// An exclusively created private job directory rooted in one destination handle.
///
/// The job can create its fixed records and state directories. Each operation
/// rechecks the held job binding. The directory handle owns a nonblocking
/// exclusive advisory lock for the lifetime of this capability.
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
		self.sync_directory_admitted(|| Ok(()))
	}

	/// Exclusively creates the private `owner.cbor` record.
	///
	/// # Errors
	///
	/// Rejects a changed job binding, a name collision or a syscall failure.
	/// The record writer owns file barriers and reconciliation.
	pub fn create_owner_record(&self) -> Result<File, StageError> {
		self.create_record(OWNER)
	}

	/// Exclusively creates the private `plan.cbor` record.
	///
	/// # Errors
	///
	/// Rejects a changed job binding, a name collision or a syscall failure.
	/// The record writer owns file barriers and reconciliation.
	pub fn create_plan_record(&self) -> Result<File, StageError> {
		self.create_record(PLAN)
	}

	fn create_record(&self, name: &str) -> Result<File, StageError> {
		self.check_current()?;
		let (file, _) = create_private_file(
			&self.directory,
			self.root.mount,
			OsStr::new(name),
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
		self.create_stage_directory_admitted(|| Ok(()))
	}

	/// Exclusively creates the fixed private `journal/` child.
	///
	/// # Errors
	///
	/// Rejects a changed job binding, a name collision or a syscall failure.
	pub fn create_journal_directory(&self) -> Result<JournalDirectory<'_>, StageError> {
		Ok(JournalDirectory(self.create_record_directory(JOURNAL)?))
	}

	/// Exclusively creates the fixed private `receipts/` child.
	///
	/// # Errors
	///
	/// Rejects a changed job binding, a name collision or a syscall failure.
	pub fn create_receipt_directory(&self) -> Result<ReceiptDirectory<'_>, StageError> {
		Ok(ReceiptDirectory(self.create_record_directory(RECEIPTS)?))
	}

	fn create_record_directory(
		&self,
		name: &'static str,
	) -> Result<RecordDirectory<'_>, StageError> {
		self.create_record_directory_admitted(name, || Ok(()))
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
pub struct JournalDirectory<'job>(RecordDirectory<'job>);

impl JournalDirectory<'_> {
	/// Returns the held journal directory identity.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.0.identity
	}

	/// Requests a barrier on the checked journal directory.
	///
	/// # Errors
	///
	/// Rejects a changed job or journal binding, or a failed directory barrier.
	pub fn sync_directory(&self) -> Result<(), StageError> {
		self.0.sync_directory()
	}

	/// Exclusively creates the private `00000000000000000001.exajnl` segment.
	///
	/// # Errors
	///
	/// Rejects a changed directory binding, a name collision or a syscall failure.
	/// The segment writer owns file barriers and reconciliation.
	pub fn create_first_segment(&self) -> Result<LinuxJournalSegment<'static>, StageError> {
		self.create_first_segment_admitted(|| Ok(()))
	}
}

/// An exclusively created receipt directory bound to one held private job.
#[derive(Debug)]
pub struct ReceiptDirectory<'job>(RecordDirectory<'job>);

impl ReceiptDirectory<'_> {
	/// Exclusively creates the private `receipt.cbor` artifact.
	///
	/// # Errors
	///
	/// Rejects a changed directory binding, a name collision or a syscall failure.
	/// The record writer owns file barriers and reconciliation.
	pub fn create_receipt_record(&self) -> Result<File, StageError> {
		self.0.create_file(RECEIPT)
	}

	/// Requests a barrier on the checked receipt directory.
	///
	/// # Errors
	///
	/// Rejects a changed job or receipt binding, or a failed directory barrier.
	pub fn sync_directory(&self) -> Result<(), StageError> {
		self.0.sync_directory()
	}
}

struct RecordDirectory<'job> {
	job: &'job JobDirectory<'job>,
	directory: File,
	identity: FileIdentity,
	name: &'static str,
}

impl RecordDirectory<'_> {
	fn sync_directory(&self) -> Result<(), StageError> {
		self.check_current()?;
		sync_directory(&self.directory)
	}

	fn create_file(&self, name: &str) -> Result<File, StageError> {
		self.create_file_admitted(name, || Ok(()))
	}

	fn check_current(&self) -> Result<(), StageError> {
		self.job.check_current()?;
		check_private_child(
			&self.job.directory,
			&self.directory,
			OsStr::new(self.name),
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
			.field("identity", &self.0.identity)
			.finish_non_exhaustive()
	}
}

impl fmt::Debug for RecordDirectory<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("RecordDirectory")
			.field("identity", &self.identity)
			.finish_non_exhaustive()
	}
}
