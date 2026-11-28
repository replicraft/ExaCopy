use std::ffi::OsStr;
use std::fs::File;

use rustix::fs;

use super::super::SourceObservation;
use super::super::handle::{FileIdentity, mount_id};
use super::super::stage::{FILE_MODE, check_named_file, check_private_child};
use super::{DestinationRoot, FIRST_SEGMENT, JOURNAL, RecordDirectory, StageError};

pub(in crate::linux) struct FreshJournalNames {
	root: DestinationRoot,
	// This duplicate keeps the job's original flock open file description alive.
	job_lock: File,
	job_name: Box<OsStr>,
	job_identity: FileIdentity,
	journal: File,
	journal_identity: FileIdentity,
}

impl FreshJournalNames {
	pub(super) fn hold(directory: &RecordDirectory<'_>) -> Result<Self, StageError> {
		let job = directory.job;
		Ok(Self {
			root: job.root.try_clone_held()?,
			job_lock: job.directory.try_clone().map_err(StageError::System)?,
			job_name: job.name.clone(),
			job_identity: job.identity,
			journal: directory
				.directory
				.try_clone()
				.map_err(StageError::System)?,
			journal_identity: directory.identity,
		})
	}

	pub(in crate::linux) fn recheck_segment(
		&self,
		segment: &File,
		identity: FileIdentity,
	) -> Result<u64, StageError> {
		self.recheck_parents()?;
		let mount = self.root.mount;
		let named = check_named_file(
			&self.journal,
			OsStr::new(FIRST_SEGMENT),
			identity,
			mount,
			FILE_MODE,
		)?;
		if mount_id(segment)? != mount {
			return Err(StageError::IdentityChanged);
		}
		let held =
			SourceObservation::capture(&fs::fstat(segment)?).map_err(StageError::ReadBack)?;
		SourceObservation::capture(&named)
			.and_then(|named| named.recheck(held))
			.map_err(StageError::ReadBack)?;
		self.recheck_parents()?;
		Ok(held.len())
	}

	fn recheck_parents(&self) -> Result<(), StageError> {
		self.root.check_current()?;
		check_private_child(
			&self.root.directory,
			&self.job_lock,
			&self.job_name,
			self.job_identity,
			self.root.mount,
		)?;
		check_private_child(
			&self.job_lock,
			&self.journal,
			OsStr::new(JOURNAL),
			self.journal_identity,
			self.root.mount,
		)
	}
}
