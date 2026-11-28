use exacopy_endpoint::ReadView;
use exacopy_endpoint::linux_recovery::{HeldPublicApplyRecords, RecoveryRecord};
use exacopy_journal::{ApplyQualification, PublicApplyAssociation, PublicApplyOwnerRecord};

use crate::linux::replay::{MAX_PUBLIC_APPLY_SUFFIX_BYTES, PublicApplyReplay};
use crate::linux::{
	InspectionError, LocalCopyPlan, MAX_PUBLIC_APPLY_RECEIPT_BYTES, PublicApplyCommitSelection,
	PublicApplyReceipt, ReceiptEvidence, RecoveryStep,
};

use super::{PublicApplyReceiptObservation, read_artifact};

type Observation<R> = Result<
	PublicApplyReceiptObservation,
	InspectionError<
		<<R as HeldPublicApplyRecords>::Record as ReadView>::Error,
		<R as HeldPublicApplyRecords>::Error,
	>,
>;

pub(super) fn observe<R: HeldPublicApplyRecords>(
	records: &mut R,
	plan: &LocalCopyPlan<'_>,
	owner: &PublicApplyOwnerRecord,
	qualification: ApplyQualification,
	history: &PublicApplyReplay,
) -> Observation<R> {
	use PublicApplyReceiptObservation as Outcome;

	let Some(receipt) = records.receipt() else {
		return Ok(Outcome::Absent);
	};
	let journal = &history.journal;
	if journal.receipt.is_none() {
		return Ok(Outcome::PresentUncommitted);
	}
	let step = RecoveryStep::Receipt;
	let receipt_bytes = read_artifact(receipt, step, MAX_PUBLIC_APPLY_RECEIPT_BYTES)?;
	receipt.check_logical_eof().map_err(step.read())?;
	let step = RecoveryStep::Journal;
	let (Some(seal), Some(verification), Some(metadata), Some(durability)) = (
		history.seal,
		journal.verification,
		journal.metadata,
		journal.durability,
	) else {
		return Err(InspectionError::RecordChanged(step));
	};
	let length = journal
		.boundary
		.offset
		.checked_sub(seal.offset)
		.and_then(|length| usize::try_from(length).ok())
		.filter(|&length| length <= MAX_PUBLIC_APPLY_SUFFIX_BYTES)
		.ok_or(InspectionError::Oversize(step))?;
	let segment = records
		.segment()
		.ok_or(InspectionError::RecordChanged(step))?;
	if segment.length() != journal.boundary.offset {
		return Err(InspectionError::RecordChanged(step));
	}
	let mut buffer = [0; MAX_PUBLIC_APPLY_SUFFIX_BYTES];
	let observed = &mut buffer[..length];
	segment
		.read_exact_at(seal.offset, observed)
		.map_err(step.read())?;
	segment.check_logical_eof().map_err(step.read())?;
	segment.recheck_inode().map_err(step.read())?;
	let manifest = owner.manifest();
	let selected = PublicApplyCommitSelection {
		seal: seal.head,
		association: PublicApplyAssociation {
			owner_digest: owner.digest(),
			public_plan: manifest.binding.public_plan,
			public_entry: manifest.binding.public_entry,
		},
		qualification,
		copy: ReceiptEvidence {
			context: plan.context(),
			entry: plan.attempt().entry,
			source: verification.source().identity,
			destination: plan.destination().root,
			target: plan.destination().component,
			stream: verification.stage(),
		},
		metadata: metadata.metadata,
		stage_directory: durability.barriers().stage_directory,
		owner_created: manifest.owner.created,
		expires_at: manifest.binding.expires_at,
	};
	Ok(
		match PublicApplyReceipt::validate_commit_boundary(&*observed, &receipt_bytes, selected) {
			Ok(head) if head == journal.boundary.head => Outcome::MatchesCommit,
			Ok(_) => return Err(InspectionError::RecordChanged(step)),
			Err(cause) => Outcome::Inconsistent(cause),
		},
	)
}
