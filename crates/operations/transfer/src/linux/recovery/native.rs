use std::io;

use exacopy_content::measure_at;
use exacopy_journal::{MAX_RANGE_PAGE_BYTES, MetadataRecorded, RangePageRef, StreamEvidence};
use exacopy_platform::linux::{
	ExtendedAttributes, RecoveryFile, RecoveryInventory, RecoveryJob, StageError,
};

use super::classify::{ObservedFile, ObservedNames};
use super::{RecoveryInspectError, RecoveryIssue, RecoveryStep, native_identity};

pub(super) fn observe_names<'inventory>(
	names: &'inventory RecoveryInventory<'_>,
) -> ObservedNames<'inventory, RecoveryFile> {
	let observe =
		|file: &'inventory RecoveryFile| ObservedFile::new(native_identity(file.identity()), file);
	ObservedNames {
		stage: names.stage().map(observe),
		target: names.target().map(observe),
		stage_directory: names.stage_directory_identity().map(native_identity),
	}
}

pub(super) fn read_checkpoint(
	job: &RecoveryJob<'_>,
	page: RangePageRef,
) -> Result<Vec<u8>, RecoveryInspectError> {
	let step = RecoveryStep::Checkpoint;
	let file = job
		.open_checkpoint_page(page.ordinal())
		.map_err(step.platform())?;
	read_artifact(&file, step, MAX_RANGE_PAGE_BYTES)
}

pub(super) fn read_artifact(
	file: &RecoveryFile,
	step: RecoveryStep,
	maximum: usize,
) -> Result<Vec<u8>, RecoveryInspectError> {
	let length = usize::try_from(file.len())
		.ok()
		.filter(|length| *length <= maximum)
		.ok_or(RecoveryInspectError::Oversize(step))?;
	let mut bytes = vec![0; length];
	file.read_exact_at(0, &mut bytes).map_err(step.read())?;
	file.recheck_observation().map_err(step.read())?;
	Ok(bytes)
}

pub(super) fn open_receipt(
	job: &RecoveryJob<'_>,
) -> Result<Option<RecoveryFile>, RecoveryInspectError> {
	match job.open_receipt() {
		Ok(file) => Ok(Some(file)),
		Err(StageError::System(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
		Err(source) => Err(RecoveryStep::Receipt.platform()(source)),
	}
}

pub(super) fn recheck_record(
	held: &RecoveryFile,
	current: Result<RecoveryFile, StageError>,
	step: RecoveryStep,
) -> Result<(), RecoveryInspectError> {
	let current = current.map_err(step.platform())?;
	match_identity(held, &current, step)
}

pub(super) fn recheck_receipt(
	job: &RecoveryJob<'_>,
	held: Option<&RecoveryFile>,
) -> Result<(), RecoveryInspectError> {
	match (held, open_receipt(job)?) {
		(None, None) => Ok(()),
		(Some(held), Some(current)) => match_identity(held, &current, RecoveryStep::Receipt),
		_ => Err(RecoveryInspectError::RecordChanged(RecoveryStep::Receipt)),
	}
}

fn match_identity(
	held: &RecoveryFile,
	current: &RecoveryFile,
	step: RecoveryStep,
) -> Result<(), RecoveryInspectError> {
	if held.identity() != current.identity() {
		return Err(RecoveryInspectError::RecordChanged(step));
	}
	held.recheck_observation().map_err(step.read())
}

pub(super) fn verify(
	file: &RecoveryFile,
	expected: StreamEvidence,
	metadata: Option<MetadataRecorded>,
	scratch: &mut [u8],
) -> Result<Option<RecoveryIssue>, RecoveryInspectError> {
	if file.len() != expected.length.get() {
		return Ok(Some(RecoveryIssue::StreamMismatch));
	}
	let digest = measure_at(file.len(), scratch, |offset, bytes| {
		file.read_exact_at(offset, bytes)
	})
	.map_err(RecoveryInspectError::ReadBack)?;
	file.check_logical_eof()
		.map_err(RecoveryStep::Stream.read())?;
	if digest.as_bytes() != expected.digest.as_bytes() {
		return Ok(Some(RecoveryIssue::StreamMismatch));
	}
	if let Some(recorded) = metadata {
		let observed = file.observation();
		let modified = observed.modified_at();
		let expected = recorded.metadata;
		let attributes = file
			.extended_attributes()
			.map_err(RecoveryStep::Stream.read())?;
		if observed.mode() != expected.mode()
			|| observed.owner() != expected.uid
			|| observed.group() != expected.gid
			|| observed.link_count() != 1
			|| modified.seconds() != expected.modified_at.seconds()
			|| modified.nanoseconds() != expected.modified_at.nanoseconds()
			|| attributes != ExtendedAttributes::NoneVisible
		{
			return Ok(Some(RecoveryIssue::MetadataMismatch));
		}
	}
	Ok(None)
}
