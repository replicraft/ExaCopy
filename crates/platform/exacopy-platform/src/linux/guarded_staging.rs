use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_apply::{
	ApplyRole, ApplyStep, ExactSourceRoot, GuardedStageDirectory, GuardedStageReader,
	GuardedStageWriter, LocalApplyAdmission,
};
use exacopy_model::CopyBinding;

use super::{
	CheckedStageError, ClosedStage, ReadError, ReadRoot, SourceFile, SourceObservation,
	SourceTimestamp, StageDirectory, StageError, WriteStage,
};

#[cfg(test)]
pub(super) mod tests;

impl ExactSourceRoot for ReadRoot {
	fn recheck_exact_regular_name(
		&self,
		name: UnixComponent<'_>,
		source: &SourceFile,
	) -> Result<(), ReadError> {
		self.recheck_regular_name(name, source)
	}
}

impl GuardedStageDirectory for StageDirectory<'_> {
	type CheckedPublishError = CheckedStageError;
	type CheckedWriter<'stage>
		= WriteStage<'stage>
	where
		Self: 'stage;

	fn create_file_admitted(
		&self,
		name: UnixComponent<'_>,
		target: UnixComponent<'_>,
		binding: CopyBinding,
		admission: &impl LocalApplyAdmission,
	) -> Result<WriteStage<'_>, StageError> {
		StageDirectory::create_file_admitted(self, name, target, binding, || {
			admission.enter(ApplyStep::Create(ApplyRole::Stage))
		})
	}

	fn sync_stage_admitted(&self, admission: &impl LocalApplyAdmission) -> Result<(), StageError> {
		self.sync_directory_admitted(|| admission.enter(ApplyStep::Sync(ApplyRole::StageDirectory)))
	}
}

impl GuardedStageWriter for WriteStage<'_> {
	type CheckedPublishError = CheckedStageError;

	fn write_window_admitted(
		&mut self,
		offset: u64,
		bytes: &[u8],
		admission: &impl LocalApplyAdmission,
	) -> Result<(), StageError> {
		self.guarded_write(offset, bytes, || {
			admission.enter(ApplyStep::Write(ApplyRole::Stage, offset, bytes.len()))
		})
	}

	fn set_len_admitted(
		&mut self,
		length: u64,
		admission: &impl LocalApplyAdmission,
	) -> Result<(), StageError> {
		self.guarded_extent(length, || {
			admission.enter(ApplyStep::SetStageExtent(length))
		})
	}

	fn flush_stage_admitted(
		&mut self,
		admission: &impl LocalApplyAdmission,
	) -> Result<(), StageError> {
		self.flush_admitted(|| admission.enter(ApplyStep::Sync(ApplyRole::Stage)))
	}
}

impl GuardedStageReader for ClosedStage<'_> {
	fn apply_metadata_admitted(
		self,
		metadata: SourceObservation,
		accessed_at: SourceTimestamp,
		admission: &impl LocalApplyAdmission,
	) -> Result<Self, StageError> {
		self.apply_metadata_admitted_with_access_time(metadata, accessed_at, |step| {
			admission.enter(step)
		})
	}

	fn seal_stage_admitted(&self, admission: &impl LocalApplyAdmission) -> Result<(), StageError> {
		self.guard_stage_seal(|| admission.enter(ApplyStep::Sync(ApplyRole::StageDirectory)))
	}
}
