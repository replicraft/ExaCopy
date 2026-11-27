//! Evidence assessment for one explicitly approved additive synchronization action.
//!
//! This pure guard receives trusted projections from an independent approval verifier,
//! current-head reader, journal, receipt verifier, and live inventory producer. It
//! returns a report for the caller's retained approval and observations.

use core::num::NonZeroU64;

use crate::sync_genesis::{
	self, FileId, GenesisRefusal, Measurement, RecheckedObservation, RootId, Scope, Selection,
};
use crate::{CopyBinding, RegularFileEvidence, SyncSide};

/// Exact independently authenticated root of the previous immutable baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Predecessor<'name> {
	/// Generation of the canonical baseline root.
	pub generation: NonZeroU64,
	/// Workflow Root commitment over the domain-separated canonical root body.
	pub digest: [u8; 32],
	/// Authorized endpoint roots in left, right order.
	pub roots: [RootId; 2],
	/// Bound owner, profile, raw basename and required evidence policy.
	pub scope: Scope<'name>,
}

/// Projection of a separately authenticated parent approval for one exclusive create.
///
/// The verifier checks the signed parent and its complete closure. The parent
/// must have exactly one create-new action with approved destination absence,
/// a separately resolved child plan, and no unresolved conflict or incomplete
/// scope. The two-way preview classifier supplies observations only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovedCreate<'name> {
	/// Previous baseline selected by the signed parent.
	pub predecessor: Predecessor<'name>,
	/// Digest of the exact signed parent plan body.
	pub parent_plan_digest: [u8; 32],
	/// Identifier of the sole approved action in that parent.
	pub action_id: [u8; 16],
	/// Digest of the exact approved create-new child plan.
	pub child_plan_digest: [u8; 32],
	/// Side holding the source. The opposite name must be absent before publication.
	pub from: SyncSide,
	/// Source identity pinned by approval.
	pub source_file: FileId,
	/// Approved source stream and required metadata evidence.
	pub source_evidence: RegularFileEvidence,
}

/// Projection of the exact durable sync action intent recorded before its effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableIntent<'name> {
	/// Parent approval and exact child action bound by the durable intent.
	pub approved: ApprovedCreate<'name>,
	/// Job, entry, run and owned stage used by the intended child effect.
	pub copy: CopyBinding,
	/// Digest identifying the exact durable intent record.
	pub digest: [u8; 32],
}

/// Projection of an independently verified successful create-new child receipt.
///
/// The verifier confirms that the exact intent predates the completed effect,
/// the expected source was read under the approved policy, verification and
/// required barriers finished, and the owned stage published exclusively to
/// the approved absent name. The receipt must be durably persisted and resolve
/// through the exact action journal association. The file ID uses the live
/// inventory's identity domain.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedReceipt<'name> {
	/// Durable action intent and child attempt recorded in the receipt.
	pub intent: DurableIntent<'name>,
	/// Digest identifying the exact verified receipt.
	pub digest: [u8; 32],
	/// Physical identity of the file published by the child.
	pub published_file: FileId,
	/// Independently read-back stream and verified required metadata of the child.
	pub evidence: RegularFileEvidence,
}

/// Evidence available for the exact copy attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EffectOutcome<'receipt, 'name> {
	/// No independently verified successful receipt is available.
	Missing,
	/// The effect or its evidence is uncertain.
	Uncertain,
	/// The successful receipt was independently verified.
	Verified(&'receipt VerifiedReceipt<'name>),
}

/// One completed full read together with its start position in the same scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostReceiptMeasurement<'name> {
	/// Producer-observed position before the first read under the bound policy.
	pub started_at: NonZeroU64,
	/// Completed measurement with EOF and required metadata under that policy.
	pub measurement: Measurement<'name>,
}

/// A complete fresh inventory attempt for the single selected subject.
///
/// The inventory producer holds the disjoint roots and allocates one sequence
/// for the receipt validation marker, the start and completion of both reads,
/// and the final name observations. These positions are producer-supplied facts.
#[derive(Debug, Eq, PartialEq)]
pub struct Postconditions<'name> {
	/// Exact held pair, subject, and fresh scan instance.
	pub selection: Selection<'name>,
	/// Exact receipt associated with the scan's validation marker.
	pub receipt_digest: [u8; 32],
	/// Position marking validation of that receipt in the scan sequence.
	pub receipt_validated_at: NonZeroU64,
	/// Left and right read intervals and completed evidence. A missing side is incomplete.
	pub measurements: [Option<PostReceiptMeasurement<'name>>; 2],
	/// Fresh final observations after both measurements, in left, right order.
	pub rechecked: [Option<RecheckedObservation<'name>>; 2],
}

/// Independent observations consumed by the report-only assessment.
#[derive(Debug, Eq, PartialEq)]
pub struct SuccessorEvidence<'receipt, 'name> {
	/// Independently read and authenticated current selection for the approved scope.
	pub current: Option<Predecessor<'name>>,
	/// Exact observed durable intent for the action.
	pub intent: Option<DurableIntent<'name>>,
	/// Receipt digest independently observed in the durable action journal for this intent.
	/// Unresolved or uncertain associations provide no digest.
	pub observed_receipt: Option<[u8; 32]>,
	/// Available child-effect evidence.
	pub outcome: EffectOutcome<'receipt, 'name>,
	/// Independently observed current postconditions on both roots.
	pub postconditions: Postconditions<'name>,
}

/// Why the evidence calls for reconciliation before advancing the baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SuccessorBlock {
	/// The independently read current predecessor is missing or differs from the approval.
	Predecessor,
	/// The predecessor generation has no representable successor.
	GenerationExhausted,
	/// No durable intent for the exact approved action was observed.
	Intent,
	/// No independently verified successful receipt was observed.
	MissingReceipt,
	/// The action result remains uncertain.
	UncertainEffect,
	/// The receipt differs from the durable intent, approved evidence or identity requirements.
	ReceiptBinding,
	/// The durable action journal does not associate this intent with the verified receipt.
	ReceiptCommitment,
	/// The postcondition scan is bound to a different verified receipt.
	PostconditionReceipt,
	/// The postconditions were measured for different roots or scope.
	PostconditionSelection,
	/// The measurements or fresh final observations do not support matching evidence.
	Postconditions(GenesisRefusal),
	/// A read interval is malformed or did not start after validating the exact receipt.
	StalePostconditions,
	/// The ordered physical files or their evidence do not match the approved effect.
	PostconditionBinding,
}

/// Report-only assessment of the supplied successor evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SuccessorDecision {
	/// All supplied evidence is consistent with the checked successor generation.
	Eligible {
		/// Generation immediately following the exact observed predecessor.
		generation: NonZeroU64,
	},
	/// The coordinator must reconcile before taking further action.
	Reconcile(SuccessorBlock),
}

/// Assesses one approved create-new action against an independently observed predecessor.
///
/// The caller preserves the scope and authority of each evidence producer.
/// The independently read head is a snapshot, so competing proposals can
/// both pass against it. A future publisher must compare the exact head and
/// activate the successor in one serialized check and update, with the held
/// postconditions revalidated at that boundary.
#[must_use]
pub fn assess<'name>(
	approved: &ApprovedCreate<'name>,
	evidence: &SuccessorEvidence<'_, 'name>,
) -> SuccessorDecision {
	use SuccessorDecision::Reconcile;

	let predecessor = approved.predecessor;
	if evidence.current != Some(predecessor) {
		return Reconcile(SuccessorBlock::Predecessor);
	}
	let Some(generation) = predecessor.generation.checked_add(1) else {
		return Reconcile(SuccessorBlock::GenerationExhausted);
	};
	let Some(intent) = &evidence.intent else {
		return Reconcile(SuccessorBlock::Intent);
	};
	if &intent.approved != approved {
		return Reconcile(SuccessorBlock::Intent);
	}
	let receipt = match evidence.outcome {
		EffectOutcome::Missing => return Reconcile(SuccessorBlock::MissingReceipt),
		EffectOutcome::Uncertain => return Reconcile(SuccessorBlock::UncertainEffect),
		EffectOutcome::Verified(receipt) => receipt,
	};
	if &receipt.intent != intent
		|| receipt.evidence != approved.source_evidence
		|| receipt.published_file == approved.source_file
	{
		return Reconcile(SuccessorBlock::ReceiptBinding);
	}
	if evidence.observed_receipt != Some(receipt.digest) {
		return Reconcile(SuccessorBlock::ReceiptCommitment);
	}
	if let Err(reason) = check_postconditions(approved, receipt, &evidence.postconditions) {
		return Reconcile(reason);
	}
	SuccessorDecision::Eligible { generation }
}

fn check_postconditions(
	approved: &ApprovedCreate<'_>,
	receipt: &VerifiedReceipt<'_>,
	postconditions: &Postconditions<'_>,
) -> Result<(), SuccessorBlock> {
	if postconditions.receipt_digest != receipt.digest {
		return Err(SuccessorBlock::PostconditionReceipt);
	}
	let selection = postconditions.selection;
	let predecessor = approved.predecessor;
	if selection.roots != predecessor.roots || selection.scope != predecessor.scope {
		return Err(SuccessorBlock::PostconditionSelection);
	}
	let matched = sync_genesis::admit(
		selection,
		postconditions
			.measurements
			.map(|read| read.map(|read| read.measurement)),
		postconditions.rechecked,
	)
	.map_err(SuccessorBlock::Postconditions)?;
	if postconditions
		.measurements
		.into_iter()
		.flatten()
		.any(|read| {
			read.started_at <= postconditions.receipt_validated_at
				|| read.started_at >= read.measurement.completed_at
		}) {
		return Err(SuccessorBlock::StalePostconditions);
	}
	let [left, right] = matched.measurements();
	let (source, target) = match approved.from {
		SyncSide::Left => (left, right),
		SyncSide::Right => (right, left),
	};
	if source.observation.file != approved.source_file
		|| target.observation.file != receipt.published_file
		|| target.evidence != receipt.evidence
	{
		return Err(SuccessorBlock::PostconditionBinding);
	}
	Ok(())
}
