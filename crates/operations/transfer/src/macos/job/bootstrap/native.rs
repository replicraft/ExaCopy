use std::fs::File;

use exacopy_journal::{DarwinFileIdentity, DarwinRootBinding, OwnerError};
use exacopy_platform::macos::staging::jobs::{JobDirectory, JobError, JournalDirectory};

use super::super::{DarwinJobProfile, JobPreparationError, native_identity};
use super::capabilities::{PrivateJob, PrivateJournalDirectory};
use super::engine::{self, BootstrapError, JobPreparation};
use crate::macos::plan::DarwinCopyPlan;

pub(in crate::macos::job) fn prepare_created_job<'job>(
	plan: &DarwinCopyPlan<'_>,
	profile: DarwinJobProfile<'_>,
	job: &'job JobDirectory<'_>,
	destination: DarwinRootBinding,
) -> Result<JobPreparation<JournalDirectory<'job>>, JobPreparationError> {
	engine::prepare(plan, profile, job, destination).map_err(JobPreparationError::from)
}

impl From<BootstrapError<JobError>> for JobPreparationError {
	fn from(error: BootstrapError<JobError>) -> Self {
		match error {
			BootstrapError::Owner(error) => Self::Owner(error),
			BootstrapError::Binding(error) => Self::Binding(error),
			BootstrapError::Artifact { step, source } => step.error()(source),
			BootstrapError::Journal(error) => Self::Journal(error),
		}
	}
}

impl PrivateJob for JobDirectory<'_> {
	type Error = JobError;
	type JournalDirectory<'job>
		= JournalDirectory<'job>
	where
		Self: 'job;

	fn owner_uid(&self) -> u32 {
		self.owner_uid()
	}

	fn identity(&self) -> Result<DarwinFileIdentity, OwnerError> {
		native_identity(self.identity())
	}

	fn write_owner_record(&self, bytes: &[u8]) -> Result<(), JobError> {
		self.write_owner_record(bytes).map(|_| ())
	}

	fn write_plan_record(&self, bytes: &[u8]) -> Result<(), JobError> {
		self.write_plan_record(bytes).map(|_| ())
	}

	fn create_journal_directory(&self) -> Result<Self::JournalDirectory<'_>, JobError> {
		self.create_journal_directory()
	}
}

impl PrivateJournalDirectory for JournalDirectory<'_> {
	type Error = JobError;

	fn create_first_segment(&self) -> Result<File, JobError> {
		self.create_first_segment()
	}
}
