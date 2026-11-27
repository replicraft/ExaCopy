//! Executable decisions compared with an independent finite namespace oracle.

use std::num::NonZeroU64;

use exacopy_model::retained_prefix::Head;
use exacopy_model::witnessed_publication::{
	Approval, CaptureBoundary, FileIdentity, HeldFile, HistoricalIntent, LiveBinding,
	NameObservation, NamespaceObservation, NativeRenameOutcome, NativeWitnessOutcome, Publication,
	RecoveryObservation, RecoveryReadback, Refusal, ScopeBinding, SubmissionObservation,
	WitnessBarriers, WitnessObservation, observe_recovery,
};

#[path = "witnessed/kernel.rs"]
mod kernel;

#[path = "witnessed/intent.rs"]
mod intent;

fn identity(slot: u64) -> FileIdentity {
	FileIdentity {
		mount: NonZeroU64::new(20).unwrap(),
		device: 41,
		inode: NonZeroU64::new(slot).unwrap(),
	}
}

fn held(slot: u64, links: u64) -> NameObservation {
	NameObservation::Held(HeldFile {
		identity: identity(slot),
		links,
	})
}

fn scope() -> ScopeBinding {
	ScopeBinding {
		subject: [1; 32],
		namespace: [2; 32],
		stage: identity(1),
		base_grant: [3; 32],
		qualification: [4; 32],
		approval: Approval {
			digest: [5; 32],
			deadline: NonZeroU64::new(100).unwrap(),
		},
	}
}

fn head(sequence: u8) -> Head {
	Head {
		sequence: u64::from(sequence),
		end: u64::from(sequence) * 100,
		digest: [sequence; 32],
	}
}

fn live(sequence: u8) -> LiveBinding {
	let scope = scope();
	LiveBinding {
		scope,
		lease: [6; 32],
		base_grant: Some(scope.base_grant),
		approval: Some(scope.approval),
		now: Some(99),
		head: head(sequence),
	}
}

fn names(
	live: LiveBinding,
	stage: NameObservation,
	witness: NameObservation,
	target: NameObservation,
) -> NamespaceObservation {
	NamespaceObservation {
		lease: live.lease,
		namespace: live.scope.namespace,
		protected: true,
		stage,
		witness,
		target,
	}
}

fn intent() -> HistoricalIntent {
	HistoricalIntent {
		head: head(7),
		scope: scope(),
	}
}

#[test]
fn recovery_requires_every_independent_observation_and_current_authority() {
	use NameObservation::{Absent, Uncertain};
	const DEFECTS: usize = 16;
	let mut positive = 0;
	for defects in 0_u32..1 << DEFECTS {
		let defective = |bit: u32| (defects & (1 << bit)) != 0;
		let mut current = live(7);
		let mut observed = names(current, Absent, held(1, 2), held(1, 2));
		if defective(0) {
			observed.stage = held(1, 2);
		}
		if defective(1) {
			observed.witness = Uncertain;
		}
		if defective(2) {
			observed.target = Absent;
		}
		if defective(3) {
			observed.target = held(2, 2);
		}
		if defective(4) {
			observed.witness = held(1, 3);
		}
		if defective(5) {
			observed.lease[0] ^= 0xff;
		}
		if defective(6) {
			observed.namespace[0] ^= 0xff;
		}
		if defective(7) {
			observed.protected = false;
		}
		if defective(8) {
			current.scope.subject[0] ^= 0xff;
		}
		if defective(9) {
			current.base_grant = None;
		}
		if defective(10) {
			current.approval = None;
		}
		if defective(11) {
			current.now = None;
		}
		if defective(12) {
			current.now = Some(100);
		}
		if defective(13) {
			current.head = head(8);
		}
		if defective(14) {
			current.scope.qualification[0] ^= 0xff;
		}
		let readback = if defective(15) {
			RecoveryReadback::Incomplete
		} else {
			RecoveryReadback::Complete
		};
		match observe_recovery(&intent(), current, observed, readback) {
			RecoveryObservation::Recovered(evidence) => {
				assert_eq!(defects, 0);
				assert_eq!(*evidence.intent(), intent());
				assert_eq!(evidence.lease(), current.lease);
				positive += 1;
			}
			RecoveryObservation::Reconcile => assert_ne!(defects, 0),
		}
	}
	assert_eq!(positive, 1);
}

fn arm_rename() -> (Publication, NamespaceObservation) {
	use NameObservation::Absent;
	let stage = names(live(2), held(1, 1), Absent, Absent);
	let mut publication =
		Publication::begin(live(2), stage, CaptureBoundary::ClosedAndSynced).unwrap();
	publication.witness_intent(live(3)).unwrap();
	let mut denied = live(3);
	denied.approval = None;
	assert_eq!(
		publication.submit_witness(denied, stage),
		Err(Refusal::Binding)
	);
	let link = publication.submit_witness(live(3), stage).unwrap();
	assert_eq!(
		publication.submit_witness(live(3), stage),
		Err(Refusal::Order)
	);
	let witnessed = names(live(4), held(1, 2), held(1, 2), Absent);
	assert_eq!(
		publication.observe_witness(link, live(3), witnessed, NativeWitnessOutcome::Linked),
		Ok(WitnessObservation::Linked)
	);
	assert_eq!(
		publication.seal_witness(live(4), witnessed, WitnessBarriers::Incomplete),
		Err(Refusal::Evidence)
	);
	assert_eq!(
		publication.rename_intent(live(7), witnessed, head(5), head(6)),
		Err(Refusal::Order)
	);
	publication
		.seal_witness(live(4), witnessed, WitnessBarriers::BothConfirmed)
		.unwrap();
	publication
		.rename_intent(live(7), witnessed, head(5), head(6))
		.unwrap();
	(publication, witnessed)
}

#[test]
fn live_one_shot_outcome_is_preserved_after_expiry_and_drift() {
	use NameObservation::Absent;
	let published = names(live(7), Absent, held(1, 2), held(1, 2));
	let mut expired = live(7);
	expired.now = Some(100);
	for drift in [false, true] {
		let (mut publication, witnessed) = arm_rename();
		assert_eq!(
			publication.submit_rename(expired, witnessed),
			Err(Refusal::Binding)
		);
		let submission = publication.submit_rename(live(7), witnessed).unwrap();
		assert_eq!(
			publication.submit_rename(live(7), witnessed),
			Err(Refusal::Order)
		);
		let mut later = expired;
		later.base_grant = None;
		if drift {
			later.head = head(8);
		}
		let outcome = publication.observe_submission(
			submission,
			later,
			published,
			NativeRenameOutcome::Success,
		);
		assert_eq!(
			outcome,
			Ok(if drift {
				SubmissionObservation::Reconcile(NativeRenameOutcome::Success)
			} else {
				SubmissionObservation::Published
			})
		);
		assert_eq!(
			publication.submit_rename(live(7), witnessed),
			Err(Refusal::Order)
		);
	}
}

#[test]
fn uncertain_outcomes_or_historical_intents_never_restore_a_live_submission() {
	use NameObservation::Absent;
	let (mut publication, witnessed) = arm_rename();
	let submission = publication.submit_rename(live(7), witnessed).unwrap();
	let incumbent = names(live(7), held(1, 2), held(1, 2), held(2, 1));
	assert_eq!(
		publication.observe_submission(
			submission,
			live(7),
			incumbent,
			NativeRenameOutcome::Uncertain
		),
		Ok(SubmissionObservation::Reconcile(
			NativeRenameOutcome::Uncertain
		))
	);
	assert_eq!(
		publication.submit_rename(live(7), witnessed),
		Err(Refusal::Order)
	);

	for boundary in [
		CaptureBoundary::HistoricalWitnessIntent,
		CaptureBoundary::HistoricalPublicationIntent,
		CaptureBoundary::IncompleteOrUncertain,
	] {
		let names_now = names(live(7), held(1, 1), Absent, Absent);
		assert!(matches!(
			Publication::begin(live(7), names_now, boundary),
			Err(Refusal::Evidence)
		));
	}
	assert_eq!(
		observe_recovery(&intent(), live(7), witnessed, RecoveryReadback::Complete),
		RecoveryObservation::Reconcile
	);
}

#[test]
fn late_witness_result_preserves_fact_but_cannot_authorize_seal() {
	use NameObservation::Absent;
	let stage = names(live(2), held(1, 1), Absent, Absent);
	let mut publication =
		Publication::begin(live(2), stage, CaptureBoundary::ClosedAndSynced).unwrap();
	publication.witness_intent(live(3)).unwrap();
	let submission = publication.submit_witness(live(3), stage).unwrap();
	let mut expired = live(3);
	expired.now = Some(100);
	let witnessed = names(expired, held(1, 2), held(1, 2), Absent);
	assert_eq!(
		publication.observe_witness(submission, expired, witnessed, NativeWitnessOutcome::Linked),
		Ok(WitnessObservation::Linked)
	);
	expired.head = head(4);
	assert_eq!(
		publication.seal_witness(expired, witnessed, WitnessBarriers::BothConfirmed),
		Err(Refusal::Binding)
	);
	assert_eq!(
		publication.submit_witness(live(3), stage),
		Err(Refusal::Order)
	);
}

#[test]
fn exact_conflict_requires_actual_native_report_and_held_incumbent() {
	let (mut publication, witnessed) = arm_rename();
	let submission = publication.submit_rename(live(7), witnessed).unwrap();
	let incumbent = names(live(7), held(1, 2), held(1, 2), held(2, 1));
	assert_eq!(
		publication.observe_submission(
			submission,
			live(7),
			incumbent,
			NativeRenameOutcome::Conflict
		),
		Ok(SubmissionObservation::Conflict)
	);
	assert_eq!(
		publication.submit_rename(live(7), witnessed),
		Err(Refusal::Order)
	);
}
