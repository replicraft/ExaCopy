//! Witness and rename authority before submission.

use exacopy_model::retained_prefix::Head;
use exacopy_model::witnessed_publication::{
	CaptureBoundary, NameObservation, NamespaceObservation, NativeWitnessOutcome, Publication,
	Refusal, WitnessBarriers, WitnessObservation,
};

use super::{head, held, live, names};

const CAPTURE: u8 = 2;
const LINK_INTENT: u8 = 3;
const SEAL: u8 = 4;
const VERIFIED: u8 = 5;
const METADATA: u8 = 6;
const RENAME_INTENT: u8 = 7;

fn private_stage() -> NamespaceObservation {
	names(
		live(CAPTURE),
		held(1, 1),
		NameObservation::Absent,
		NameObservation::Absent,
	)
}

fn witnessed_stage() -> NamespaceObservation {
	names(live(SEAL), held(1, 2), held(1, 2), NameObservation::Absent)
}

fn capture_closed(stage: NamespaceObservation) -> Publication {
	Publication::begin(live(CAPTURE), stage, CaptureBoundary::ClosedAndSynced)
		.expect("the exact private stage can enter witnessed closeout")
}

fn witness_linked() -> (Publication, NamespaceObservation) {
	let stage = private_stage();
	let mut publication = capture_closed(stage);
	publication
		.witness_intent(live(LINK_INTENT))
		.expect("the adjacent durable witness intent");
	let submission = publication
		.submit_witness(live(LINK_INTENT), stage)
		.expect("the exact protected names allow one link");
	let witnessed = witnessed_stage();
	assert_eq!(
		publication.observe_witness(
			submission,
			live(LINK_INTENT),
			witnessed,
			NativeWitnessOutcome::Linked,
		),
		Ok(WitnessObservation::Linked),
		"the observed link leaves the original inode under both protected names"
	);
	(publication, witnessed)
}

fn witness_sealed() -> (Publication, NamespaceObservation) {
	let (mut publication, witnessed) = witness_linked();
	publication
		.seal_witness(live(SEAL), witnessed, WitnessBarriers::BothConfirmed)
		.expect("both witnessed names and barriers are confirmed");
	(publication, witnessed)
}

#[test]
fn capture_admission_requires_live_approval_for_the_selected_scope() {
	let stage = private_stage();
	let mut capture = live(CAPTURE);
	capture.now = Some(capture.scope.approval.deadline.get());
	assert_eq!(
		Publication::begin(capture, stage, CaptureBoundary::ClosedAndSynced),
		Err(Refusal::Binding),
		"the consent's exclusive deadline has passed before witnessed closeout"
	);
}

#[test]
fn occupied_witness_or_extra_stage_alias_refuses_link_before_submission() {
	let stage = private_stage();
	for (case, observed) in [
		(
			"protected witness name already occupied",
			NamespaceObservation {
				witness: held(2, 1),
				..stage
			},
		),
		(
			"extra link to the private stage",
			NamespaceObservation {
				stage: held(1, 2),
				..stage
			},
		),
	] {
		assert!(
			matches!(
				Publication::begin(live(CAPTURE), observed, CaptureBoundary::ClosedAndSynced),
				Err(Refusal::Evidence)
			),
			"{case} at capture admission"
		);
		let mut publication = capture_closed(stage);
		publication
			.witness_intent(live(LINK_INTENT))
			.expect("clean capture can record witness intent");
		assert_eq!(
			publication.submit_witness(live(LINK_INTENT), observed),
			Err(Refusal::Evidence),
			"{case} at the effect gate"
		);
	}
}

#[test]
fn witness_intent_and_submission_use_the_exact_current_head_and_lease() {
	let stage = private_stage();
	let mut publication = capture_closed(stage);
	assert_eq!(
		publication.witness_intent(live(SEAL)),
		Err(Refusal::Binding),
		"skipping a frame cannot arm the witness link"
	);
	assert_eq!(
		publication.submit_witness(live(LINK_INTENT), stage),
		Err(Refusal::Order),
		"refused witness evidence leaves submission unarmed"
	);
	let current = live(LINK_INTENT);
	publication
		.witness_intent(current)
		.expect("the independently selected adjacent successor");
	let mut other_lease = current;
	other_lease.lease[0] ^= 0xff;
	let mut other_lease_names = stage;
	other_lease_names.lease = other_lease.lease;
	assert_eq!(
		publication.submit_witness(other_lease, other_lease_names),
		Err(Refusal::Binding),
		"another lease cannot submit an existing intent even with its own observations"
	);
	let mut other_head = current;
	other_head.head.digest[0] ^= 0xff;
	assert_eq!(
		publication.submit_witness(other_head, stage),
		Err(Refusal::Binding),
		"same sequence and end with another digest is a different accepted head"
	);
}

#[test]
fn witness_seal_rechecks_aliases_and_the_immediate_successor() {
	let (mut publication, witnessed) = witness_linked();
	assert_eq!(
		publication.seal_witness(live(LINK_INTENT), witnessed, WitnessBarriers::BothConfirmed),
		Err(Refusal::Binding),
		"recording the link intent cannot establish a separately confirmed seal"
	);

	let unconfirmed = NamespaceObservation {
		witness: NameObservation::Uncertain,
		..witnessed
	};
	assert_eq!(
		publication.seal_witness(live(SEAL), unconfirmed, WitnessBarriers::BothConfirmed),
		Err(Refusal::Evidence),
		"confirmed barriers alone cannot establish current witness custody"
	);
	assert_eq!(
		publication.rename_intent(
			live(RENAME_INTENT),
			witnessed,
			head(VERIFIED),
			head(METADATA),
		),
		Err(Refusal::Order),
		"neither rejected seal allows a publication intent"
	);
}

#[test]
fn verification_metadata_and_rename_intent_require_one_durable_successor_chain() {
	let verification = head(VERIFIED);
	let metadata = head(METADATA);
	let intent = live(RENAME_INTENT);
	for (case, verified, applied, recorded) in [
		(
			"verification reuses the witnessed seal digest",
			Head {
				digest: head(SEAL).digest,
				..verification
			},
			metadata,
			intent.head,
		),
		(
			"metadata reports no growth since verification",
			verification,
			Head {
				end: verification.end,
				..metadata
			},
			intent.head,
		),
		(
			"intent skips a sequence after metadata",
			verification,
			metadata,
			Head {
				sequence: intent.head.sequence + 1,
				..intent.head
			},
		),
	] {
		let (mut publication, witnessed) = witness_sealed();
		let mut reported = intent;
		reported.head = recorded;
		assert_eq!(
			publication.rename_intent(reported, witnessed, verified, applied),
			Err(Refusal::Binding),
			"{case}"
		);
		assert_eq!(
			publication.submit_rename(intent, witnessed),
			Err(Refusal::Order),
			"{case} cannot leave a rename armed"
		);
	}

	let (mut publication, witnessed) = witness_sealed();
	publication
		.rename_intent(intent, witnessed, verification, metadata)
		.expect("the complete adjacent closeout admits live intent");
	let submission = publication
		.submit_rename(intent, witnessed)
		.expect("the intact closeout allows a live submission");
	assert_eq!(
		submission.binding(),
		(intent.head, intent.scope),
		"the native gate receives the exact intent head and scope"
	);
}

#[test]
fn rename_requires_target_absence_at_both_intent_and_submission() {
	let intent = live(RENAME_INTENT);
	for (case, target) in [
		("new incumbent", held(2, 1)),
		("inconclusive lookup", NameObservation::Uncertain),
	] {
		let (mut publication, witnessed) = witness_sealed();
		let observed = NamespaceObservation {
			target,
			..witnessed
		};
		assert_eq!(
			publication.rename_intent(intent, observed, head(VERIFIED), head(METADATA)),
			Err(Refusal::Evidence),
			"{case} blocks recording live rename authority"
		);

		let (mut publication, witnessed) = witness_sealed();
		publication
			.rename_intent(intent, witnessed, head(VERIFIED), head(METADATA))
			.expect("the target was positively absent when live intent was confirmed");
		assert_eq!(
			publication.submit_rename(intent, observed),
			Err(Refusal::Evidence),
			"{case} blocks the native effect gate even after durable intent"
		);
	}
}
