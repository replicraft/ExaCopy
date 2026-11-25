use std::io;

use exacopy_platform::linux::{RecoveryFile, RecoveryJob, StageError};

use super::super::{
	CopyReceipt, JournalReplay, LocalCopyPlan, MAX_COPY_RECEIPT_BYTES, ReceiptEvidence,
};
use super::{RecoveryInspectError, RecoveryStep};

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

pub(super) fn check_receipt(
	file: &RecoveryFile,
	plan: &LocalCopyPlan<'_>,
	journal: &JournalReplay,
) -> Result<(), RecoveryInspectError> {
	let bytes = read_artifact(file, RecoveryStep::Receipt, MAX_COPY_RECEIPT_BYTES)?;
	let receipt = CopyReceipt::decode(&bytes).map_err(RecoveryInspectError::Receipt)?;
	let Some(verification) = journal.verification else {
		return Err(RecoveryInspectError::ReceiptBinding);
	};
	if journal.durability.is_none() {
		return Err(RecoveryInspectError::ReceiptBinding);
	}
	let expected = ReceiptEvidence {
		context: plan.context(),
		entry: plan.attempt().entry,
		source: plan.source().file_identity,
		destination: plan.destination().root,
		target: plan.destination().component,
		stream: verification.stage(),
	};
	let durability = match journal.receipt {
		Some(commit) if commit.digest().as_bytes() == &receipt.digest() => commit.durability(),
		Some(_) => return Err(RecoveryInspectError::ReceiptBinding),
		None => journal
			.durability_head
			.ok_or(RecoveryInspectError::ReceiptBinding)?,
	};
	if receipt.evidence() != expected || receipt.durability_frame() != durability {
		return Err(RecoveryInspectError::ReceiptBinding);
	}
	Ok(())
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
