use std::fs::File;

use exacopy_journal::{DarwinFileIdentity, OwnerError};
use exacopy_platform::macos::staging::jobs::{JobDirectory, JobError, JournalDirectory};

use exacopy_transfer::macos::job::bootstrap::{
	BootstrapError, PrivateJob, PrivateJournalDirectory,
};

use super::{JobPreparationError, native_identity};

pub(super) struct NativeJob<'job>(pub(super) &'job JobDirectory<'job>);
pub(super) struct NativeJournalDirectory<'job>(pub(super) JournalDirectory<'job>);

impl From<BootstrapError<JobError>> for JobPreparationError {
	fn from(error: BootstrapError<JobError>) -> Self {
		match error {
			BootstrapError::Owner(error) => Self::Owner(error),
			BootstrapError::Binding(error) => Self::Binding(error),
			BootstrapError::Artifact { step, source } => Self::Artifact { step, source },
			BootstrapError::Journal(error) => Self::Journal(error),
		}
	}
}

impl PrivateJob for NativeJob<'_> {
	type Error = JobError;
	type JournalDirectory<'job>
		= NativeJournalDirectory<'job>
	where
		Self: 'job;

	fn owner_uid(&self) -> u32 {
		self.0.owner_uid()
	}

	fn identity(&self) -> Result<DarwinFileIdentity, OwnerError> {
		native_identity(self.0.identity())
	}

	fn write_owner_record(&self, bytes: &[u8]) -> Result<(), JobError> {
		self.0.write_owner_record(bytes).map(|_| ())
	}

	fn write_plan_record(&self, bytes: &[u8]) -> Result<(), JobError> {
		self.0.write_plan_record(bytes).map(|_| ())
	}

	fn create_journal_directory(&self) -> Result<Self::JournalDirectory<'_>, JobError> {
		self.0
			.create_journal_directory()
			.map(NativeJournalDirectory)
	}
}

impl PrivateJournalDirectory for NativeJournalDirectory<'_> {
	type Error = JobError;

	fn create_first_segment(&self) -> Result<File, JobError> {
		self.0.create_first_segment()
	}
}
