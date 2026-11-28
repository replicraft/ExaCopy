use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::fs::FileExt as _;

use exacopy_endpoint::linux_apply::{
	ApplyJobRecord, ApplyRole, ApplyStep, GuardedCopyJob, GuardedJobRoot, GuardedJournalDirectory,
	HeldJobRecord, LocalApplyAdmission,
};
use exacopy_endpoint::linux_publication::{FreshReceiptError, FreshReceiptWorkspace};
use exacopy_endpoint::{UnixComponent, read_exact_at};
use rustix::fs::{self, OFlags};

use super::super::CheckedStageError;
use super::super::handle::{FileIdentity, mount_id};
use super::super::source::{
	ReadError, SourceObservation, check_logical_eof, reopen_regular_without_atime,
};
use super::super::stage::{
	FILE_MODE, check_named_file, create_private_file_admitted, write_admitted,
};
use super::checkpoint::CHECKPOINTS;
use super::{
	CheckpointDirectory, DestinationRoot, JobDirectory, JobDirectoryCreationError,
	JournalDirectory, LinuxJournalSegment, OWNER, PLAN, StageDirectory, StageError,
};

// The common native limit covers both fixed-role records. Their codecs enforce
// their own exact, generally smaller lengths.
const MAX_JOB_RECORD_BYTES: usize = 64 * 1024;

#[cfg(test)]
mod tests;

/// Read-only pin from the original creation descriptor of one fixed job artifact.
pub struct NativeHeldJobRecord {
	job: FileIdentity,
	role: ApplyJobRecord,
	file: File,
	observation: SourceObservation,
}

impl std::fmt::Debug for NativeHeldJobRecord {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter
			.debug_struct("NativeHeldJobRecord")
			.field("role", &self.role)
			.field("identity", &self.observation.identity())
			.finish_non_exhaustive()
	}
}

impl<'root> GuardedJobRoot<'root> for DestinationRoot {
	type CreateError = JobDirectoryCreationError;

	fn create_job_admitted(
		&'root self,
		name: UnixComponent<'_>,
		admission: &impl LocalApplyAdmission,
	) -> Result<JobDirectory<'root>, Self::CreateError> {
		self.create_job_directory_admitted(name, || {
			admission.enter(ApplyStep::Create(ApplyRole::Job))
		})
	}

	fn sync_destination_admitted(
		&self,
		admission: &impl LocalApplyAdmission,
	) -> Result<(), StageError> {
		self.sync_directory_admitted(|| admission.enter(ApplyStep::Sync(ApplyRole::Destination)))
	}
}

impl GuardedCopyJob for JobDirectory<'_> {
	type HeldRecord = NativeHeldJobRecord;
	type CheckedPublishError = CheckedStageError;
	type CheckedJournal<'job>
		= JournalDirectory<'job>
	where
		Self: 'job;
	type CheckedStage<'job>
		= StageDirectory<'job>
	where
		Self: 'job;
	type CheckedCheckpoints<'job>
		= CheckpointDirectory<'job>
	where
		Self: 'job;

	fn seal_job_record(
		&self,
		role: ApplyJobRecord,
		bytes: &[u8],
		admission: &impl LocalApplyAdmission,
	) -> Result<NativeHeldJobRecord, StageError> {
		if bytes.is_empty() || bytes.len() > MAX_JOB_RECORD_BYTES {
			return Err(StageError::InvalidLength);
		}
		let (name, effect_role) = record_role(role);
		self.check_current()?;
		let (writer, created) = create_private_file_admitted(
			&self.directory,
			self.root.mount,
			name,
			OFlags::RDWR,
			|| admission.enter(ApplyStep::Create(effect_role)),
		)?;
		write_admitted(
			0,
			bytes,
			|| admission.enter(ApplyStep::Write(effect_role, 0, bytes.len())),
			|position, remaining| writer.write_at(remaining, position),
		)?;
		let identity = FileIdentity::from_stat(&created);
		let check = || {
			self.check_current()?;
			let named =
				check_named_file(&self.directory, name, identity, self.root.mount, FILE_MODE)?;
			SourceObservation::capture(&named).map_err(StageError::ReadBack)
		};
		let written = check()?;
		if u64::try_from(bytes.len()) != Ok(written.len()) {
			return Err(StageError::InvalidLength);
		}
		{
			let _guard = admission
				.enter(ApplyStep::Sync(effect_role))
				.map_err(StageError::Admission)?;
			writer.sync_all().map_err(StageError::BarrierFailed)?;
		}
		let (file, stat) = reopen_regular_without_atime(&writer).map_err(StageError::ReadBack)?;
		let held = SourceObservation::capture(&stat).map_err(StageError::ReadBack)?;
		if held.identity() != identity || mount_id(&file)? != self.root.mount {
			return Err(StageError::IdentityChanged);
		}
		written.recheck(held).map_err(StageError::ReadBack)?;
		drop(writer);
		let record = NativeHeldJobRecord {
			job: self.identity(),
			role,
			file,
			observation: held,
		};
		record.recheck(self)?;
		Ok(record)
	}

	fn create_journal_admitted(
		&self,
		admission: &impl LocalApplyAdmission,
	) -> Result<JournalDirectory<'_>, StageError> {
		self.create_journal_directory_admitted(|| {
			admission.enter(ApplyStep::Create(ApplyRole::JournalDirectory))
		})
	}

	fn create_stage_admitted(
		&self,
		admission: &impl LocalApplyAdmission,
	) -> Result<StageDirectory<'_>, StageError> {
		self.create_stage_directory_admitted(|| {
			admission.enter(ApplyStep::Create(ApplyRole::StageDirectory))
		})
	}

	fn create_checkpoints_admitted(
		&self,
		admission: &impl LocalApplyAdmission,
	) -> Result<CheckpointDirectory<'_>, StageError> {
		self.create_record_directory_admitted(CHECKPOINTS, || {
			admission.enter(ApplyStep::Create(ApplyRole::CheckpointDirectory))
		})
		.map(CheckpointDirectory)
	}

	fn sync_job_admitted(&self, admission: &impl LocalApplyAdmission) -> Result<(), StageError> {
		self.sync_directory_admitted(|| admission.enter(ApplyStep::Sync(ApplyRole::Job)))
	}

	fn seal_fresh_receipt_admitted(
		&self,
		bytes: &[u8],
		admission: &impl LocalApplyAdmission,
	) -> Result<<Self as FreshReceiptWorkspace>::HeldReceipt<'_>, FreshReceiptError<StageError>>
	{
		super::receipt::seal_admitted(self, bytes, admission)
	}
}

impl GuardedJournalDirectory for JournalDirectory<'_> {
	fn create_first_segment_admitted(
		&self,
		admission: &impl LocalApplyAdmission,
	) -> Result<LinuxJournalSegment<'static>, StageError> {
		JournalDirectory::create_first_segment_admitted(self, || {
			admission.enter(ApplyStep::Create(ApplyRole::FirstSegment))
		})
	}

	fn sync_journal_admitted(
		&self,
		admission: &impl LocalApplyAdmission,
	) -> Result<(), StageError> {
		self.sync_directory_admitted(|| {
			admission.enter(ApplyStep::Sync(ApplyRole::JournalDirectory))
		})
	}
}

impl HeldJobRecord<JobDirectory<'_>> for NativeHeldJobRecord {
	type Error = StageError;

	fn read_exact_job_record(
		&self,
		job: &JobDirectory<'_>,
		output: &mut [u8],
	) -> Result<(), Self::Error> {
		if output.is_empty()
			|| output.len() > MAX_JOB_RECORD_BYTES
			|| u64::try_from(output.len()) != Ok(self.observation.len())
		{
			return Err(StageError::InvalidLength);
		}
		self.recheck(job)?;
		read_exact_at(0, output, |position, remaining| {
			self.file.read_at(remaining, position)
		})
		.map_err(ReadError::Io)
		.map_err(StageError::ReadBack)?;
		check_logical_eof(&self.file, self.observation.len()).map_err(StageError::ReadBack)?;
		self.recheck(job)
	}
}

impl NativeHeldJobRecord {
	fn recheck(&self, job: &JobDirectory<'_>) -> Result<(), StageError> {
		if job.identity() != self.job || mount_id(&self.file)? != job.root.mount {
			return Err(StageError::IdentityChanged);
		}
		job.check_current()?;
		let (name, _) = record_role(self.role);
		let named = check_named_file(
			&job.directory,
			name,
			self.observation.identity(),
			job.root.mount,
			FILE_MODE,
		)?;
		let held = fs::fstat(&self.file)?;
		for observation in [&named, &held] {
			self.observation
				.recheck(SourceObservation::capture(observation).map_err(StageError::ReadBack)?)
				.map_err(StageError::ReadBack)?;
		}
		job.check_current()
	}
}

fn record_role(role: ApplyJobRecord) -> (&'static OsStr, ApplyRole) {
	match role {
		ApplyJobRecord::Owner => (OsStr::new(OWNER), ApplyRole::Owner),
		ApplyJobRecord::PrivatePlan => (OsStr::new(PLAN), ApplyRole::PrivatePlan),
	}
}
