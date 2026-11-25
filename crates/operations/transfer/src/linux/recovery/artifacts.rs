use exacopy_content::CheckpointCandidate;
use exacopy_journal::{JournalContext, RangePage, RangePageRef};

use super::super::{CopyReceipt, JournalReplay, LocalCopyPlan, ReceiptEvidence};
use super::RecoveryInspectError;

pub(super) fn load_range_pages(
	journal: &JournalReplay,
	length: u64,
	mut read_page: impl FnMut(RangePageRef) -> Result<Vec<u8>, RecoveryInspectError>,
) -> Result<Vec<CheckpointCandidate>, RecoveryInspectError> {
	let mut covered = 0_u64;
	let mut ranges = Vec::with_capacity(journal.checkpoints.len());
	for checkpoint in &journal.checkpoints {
		let bytes = read_page(checkpoint.page)?;
		let page = RangePage::decode(&bytes).map_err(RecoveryInspectError::Checkpoint)?;
		if page.reference() != checkpoint.page
			|| page.source() != checkpoint.source
			|| page.offset() != covered
		{
			return Err(RecoveryInspectError::CheckpointBinding);
		}
		covered = covered
			.checked_add(page.length())
			.filter(|end| *end <= length)
			.ok_or(RecoveryInspectError::CheckpointBinding)?;
		ranges.push(CheckpointCandidate {
			offset: page.offset(),
			length: page.length(),
			digest: *page.digest().as_bytes(),
		});
	}
	Ok(ranges)
}

pub(super) fn check_receipt(
	bytes: &[u8],
	plan: &LocalCopyPlan<'_>,
	journal: &JournalReplay,
) -> Result<(), RecoveryInspectError> {
	let receipt = CopyReceipt::decode(bytes).map_err(RecoveryInspectError::Receipt)?;
	let Some(verification) = journal.verification else {
		return Err(RecoveryInspectError::ReceiptBinding);
	};
	let Some(intent) = journal.intent.filter(|_| journal.durability.is_some()) else {
		return Err(RecoveryInspectError::ReceiptBinding);
	};
	let expected = ReceiptEvidence {
		context: JournalContext {
			epoch: intent.epoch,
			..plan.context()
		},
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
