use std::io::Cursor;

use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
use exacopy_journal::{
	JournalEntryId, OwnerError, OwnerRecord, PublicationPrimitive, PublishIntent,
	PublishIntentContext, PublishIntentTarget, VerificationRecorded,
};

use crate::linux::JournalReplayError;

use super::*;

mod fixture;
mod reconcile;

use fixture::{
	Artifact, BYTES, Fixture, OTHER, STAGE, journal_payloads, name, owner, plan, profile_id,
	serialize, signer,
};

#[test]
fn absent_bootstrap_artifacts_are_distinct_and_do_not_authorize_inventory() {
	let mut fixture = Fixture::new(0, None);
	fixture.journal = None;
	assert!(matches!(
		fixture.inspect(),
		Ok(PublicStageInspection::Authenticated {
			history: PublicStageHistory::JournalMissing,
			..
		})
	));
	fixture.plan = None;
	assert!(matches!(
		fixture.inspect(),
		Ok(PublicStageInspection::Authenticated {
			history: PublicStageHistory::PlanMissing,
			..
		})
	));
	fixture.missing_plan_error = true;
	assert!(matches!(
		fixture.inspect(),
		Err(InspectionError::Platform {
			step: RecoveryStep::Plan,
			..
		})
	));
	fixture.owner = None;
	assert_eq!(
		fixture.inspect().ok(),
		Some(PublicStageInspection::OwnerMissing)
	);
	assert_eq!(fixture.inventory_calls.get(), 0);
}

#[test]
fn truncated_required_artifacts_never_reach_namespace_observations() {
	let mut fixture = Fixture::new(5, Some(BYTES));
	let authentic = fixture.owner.clone().unwrap();
	fixture.owner.as_mut().unwrap().bytes.get_mut().truncate(9);
	assert!(matches!(fixture.inspect(), Err(InspectionError::Owner(_))));
	fixture.owner = Some(authentic);
	fixture.plan.as_mut().unwrap().bytes.get_mut().truncate(9);
	assert!(matches!(fixture.inspect(), Err(InspectionError::Plan(_))));
	assert_eq!(fixture.inventory_calls.get(), 0);
}

#[test]
fn current_bytes_and_complete_bound_seal_are_needed_for_verified_stage() {
	use PublicStageObservation::*;
	assert_eq!(Fixture::new(0, None).observation(), EmptyJournal);
	assert_eq!(Fixture::new(1, None).observation(), RetainedPreparation);
	assert_eq!(
		Fixture::new(2, Some(BYTES)).observation(),
		RetainedPartialStage
	);
	assert_eq!(
		Fixture::new(4, Some(BYTES)).observation(),
		RetainedPartialStage
	);
	assert_eq!(
		Fixture::new(5, Some(BYTES)).observation(),
		RetainedVerifiedStage
	);
	assert_eq!(
		Fixture::new(5, Some(OTHER)).observation(),
		RequiresReconciliation(RecoveryIssue::StreamMismatch)
	);
	assert_eq!(
		Fixture::new(5, None).observation(),
		RequiresReconciliation(RecoveryIssue::MissingStageAndTarget)
	);

	let mut fixture = Fixture::new(5, Some(BYTES));
	let bytes = fixture.journal.as_mut().unwrap().bytes.get_mut();
	bytes.pop();
	assert_eq!(
		fixture.observation(),
		RequiresReconciliation(RecoveryIssue::TornJournal)
	);
	fixture.target = Some(Artifact::new(STAGE, BYTES.to_vec()));
	assert_eq!(fixture.observation(), UnexpectedTarget);
}

#[test]
fn altered_approval_and_unsupported_suffix_refuse_before_inventory() {
	let mut fixture = Fixture::new(5, Some(BYTES));
	let plan = plan();
	let owner = owner(plan);
	let wrong = journal_payloads(plan, &owner, OTHER);
	fixture.journal.as_mut().unwrap().bytes = Cursor::new(serialize(wrong));
	assert!(matches!(
		fixture.inspect(),
		Err(InspectionError::Journal(
			JournalReplayError::RecordBinding {
				kind: FrameKind::VerificationRecorded
			}
		))
	));
	for kind in [FrameKind::PublishIntent, FrameKind::RecoveryStarted] {
		let mut frames = journal_payloads(plan, &owner, BYTES);
		let payload = if kind == FrameKind::PublishIntent {
			let bytes = serialize(frames.clone());
			let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());
			let verification = (0..4)
				.map(|_| reader.next_frame().unwrap().unwrap())
				.last()
				.unwrap();
			let verification = VerificationRecorded::from_frame(&verification).unwrap();
			let context = plan.context();
			PublishIntent {
				context: PublishIntentContext {
					job: context.job,
					epoch: context.epoch,
					entry: plan.attempt().entry,
					effect_sequence: 1,
					plan_digest: context.plan_digest,
				},
				target: PublishIntentTarget {
					stage: STAGE,
					parent: plan.destination().root.identity,
					component: plan.destination().component,
					verification_digest: verification.record_digest(),
					primitive: PublicationPrimitive::LinuxRenameNoReplace,
				},
			}
			.encode()
		} else {
			vec![0]
		};
		frames.push((kind, payload));
		fixture.journal.as_mut().unwrap().bytes = Cursor::new(serialize(frames));
		assert!(
			matches!(fixture.inspect(), Err(InspectionError::Journal(JournalReplayError::UnexpectedRecord { found, .. })) if found == kind)
		);
	}
	assert_eq!(fixture.inventory_calls.get(), 0);
	assert!(matches!(
		super::super::inspect_with_job(
			&fixture,
			name(b"job"),
			RecoveryProfile {
				id: profile_id(),
				verifying_key: &signer().verifying_key()
			},
			&mut [0; 4]
		),
		Err(InspectionError::Owner(OwnerError::WrongDomain)),
	));
	assert_eq!(
		OwnerRecord::decode(owner.as_bytes(), profile_id(), &signer().verifying_key()),
		Err(OwnerError::WrongDomain)
	);
}

#[test]
fn signed_private_attempt_substitution_stops_before_reading_the_namespace() {
	let mut fixture = Fixture::new(5, Some(BYTES));
	let signed = owner(plan());
	let mut manifest = signed.manifest().clone();
	manifest.binding.private_entry = JournalEntryId::from_bytes([0x63; 16]);
	let substituted = PublicApplyOwnerRecord::sign(manifest, &signer()).unwrap();
	fixture.owner.as_mut().unwrap().bytes = Cursor::new(substituted.as_bytes().to_vec());
	assert!(matches!(
		fixture.inspect(),
		Err(InspectionError::PlanBinding)
	));
	assert_eq!(fixture.inventory_calls.get(), 0);
}
