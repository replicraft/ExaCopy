use exacopy_content::measure_at;
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_recovery::{RecoveryInventoryView, RecoveryJobView, RecoveryRecord};
use exacopy_endpoint::linux_staging::ExtendedAttributes;
use exacopy_journal::{
	LinuxFileIdentity, MAX_RANGE_PAGE_BYTES, MetadataRecorded, RangePageRef, StreamEvidence,
};

use super::classify::{ObservedFile, ObservedNames};
use super::{InspectionError, RecoveryIssue, RecoveryStep};

type JobInspectionError<J> =
	InspectionError<<J as RecoveryJobView>::ReadError, <J as RecoveryJobView>::NamespaceError>;

pub(super) fn observe_names<'inventory, I: RecoveryInventoryView>(
	names: &'inventory I,
) -> ObservedNames<'inventory, I::Record> {
	let observe = |file: &'inventory I::Record| {
		ObservedFile::new(record_identity(file.identity().into()), file)
	};
	ObservedNames {
		stage: names.stage().map(observe),
		target: names.target().map(observe),
		stage_directory: names.stage_directory_identity().map(record_identity),
	}
}

pub(super) fn read_checkpoint<J: RecoveryJobView>(
	job: &J,
	page: RangePageRef,
) -> Result<Vec<u8>, JobInspectionError<J>> {
	let step = RecoveryStep::Checkpoint;
	let file = job
		.open_checkpoint(page.ordinal())
		.map_err(step.platform())?;
	read_artifact(&file, step, MAX_RANGE_PAGE_BYTES)
}

pub(super) fn read_artifact<F: RecoveryRecord, N>(
	file: &F,
	step: RecoveryStep,
	maximum: usize,
) -> Result<Vec<u8>, InspectionError<F::Error, N>> {
	let length = usize::try_from(file.length())
		.ok()
		.filter(|length| *length <= maximum)
		.ok_or(InspectionError::Oversize(step))?;
	let mut bytes = vec![0; length];
	file.read_exact_at(0, &mut bytes).map_err(step.read())?;
	file.recheck_inode().map_err(step.read())?;
	Ok(bytes)
}

pub(super) fn open_receipt<J: RecoveryJobView>(
	job: &J,
) -> Result<Option<J::Record>, JobInspectionError<J>> {
	job.open_optional_receipt()
		.map_err(RecoveryStep::Receipt.platform())
}

pub(super) fn recheck_record<F: RecoveryRecord, N>(
	held: &F,
	current: Result<F, N>,
	step: RecoveryStep,
) -> Result<(), InspectionError<F::Error, N>> {
	let current = current.map_err(step.platform())?;
	match_identity(held, &current, step)
}

pub(super) fn recheck_receipt<J: RecoveryJobView>(
	job: &J,
	held: Option<&J::Record>,
) -> Result<(), JobInspectionError<J>> {
	match (held, open_receipt(job)?) {
		(None, None) => Ok(()),
		(Some(held), Some(current)) => match_identity(held, &current, RecoveryStep::Receipt),
		_ => Err(InspectionError::RecordChanged(RecoveryStep::Receipt)),
	}
}

fn match_identity<F: RecoveryRecord, N>(
	held: &F,
	current: &F,
	step: RecoveryStep,
) -> Result<(), InspectionError<F::Error, N>> {
	if held.identity() != current.identity() {
		return Err(InspectionError::RecordChanged(step));
	}
	held.recheck_inode().map_err(step.read())
}

pub(super) fn verify<F: RecoveryRecord, N>(
	file: &F,
	expected: StreamEvidence,
	metadata: Option<MetadataRecorded>,
	scratch: &mut [u8],
) -> Result<Option<RecoveryIssue>, InspectionError<F::Error, N>> {
	if file.length() != expected.length.get() {
		return Ok(Some(RecoveryIssue::StreamMismatch));
	}
	let digest = measure_at(file.length(), scratch, |offset, bytes| {
		file.read_exact_at(offset, bytes)
	})
	.map_err(InspectionError::ReadBack)?;
	file.check_logical_eof()
		.map_err(RecoveryStep::Stream.read())?;
	if digest.as_bytes() != expected.digest.as_bytes() {
		return Ok(Some(RecoveryIssue::StreamMismatch));
	}
	if let Some(recorded) = metadata {
		let observed = file.observation();
		let modified = observed.modified_at;
		let expected = recorded.metadata;
		let attributes = file
			.extended_attributes()
			.map_err(RecoveryStep::Stream.read())?;
		if observed.mode != expected.mode()
			|| observed.owner != expected.uid
			|| observed.group != expected.gid
			|| observed.links != 1
			|| modified.seconds != expected.modified_at.seconds()
			|| modified.nanoseconds != expected.modified_at.nanoseconds()
			|| attributes != ExtendedAttributes::NoneVisible
		{
			return Ok(Some(RecoveryIssue::MetadataMismatch));
		}
	}
	Ok(None)
}

pub(super) const fn record_identity(identity: JobFileIdentity) -> LinuxFileIdentity {
	LinuxFileIdentity::new(identity.device, identity.inode)
}
