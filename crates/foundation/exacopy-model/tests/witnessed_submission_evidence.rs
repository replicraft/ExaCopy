//! Checks the attribution and namespace evidence of spent witnessed submissions.

use std::num::NonZeroU64;

use exacopy_model::retained_prefix::Head;
use exacopy_model::witnessed_publication::{
	Approval, CaptureBoundary, FileIdentity, HeldFile, LiveBinding, NameObservation,
	NamespaceObservation, NativeRenameOutcome, NativeWitnessOutcome, Publication, Refusal,
	RenameSubmission, ScopeBinding, SubmissionObservation, WitnessBarriers, WitnessObservation,
	WitnessSubmission,
};

use NameObservation::{Absent, Held, Uncertain};

fn identity(inode: u64) -> FileIdentity {
	FileIdentity {
		mount: NonZeroU64::new(20).unwrap(),
		device: 41,
		inode: NonZeroU64::new(inode).unwrap(),
	}
}

fn head(sequence: u8) -> Head {
	Head {
		sequence: u64::from(sequence),
		end: u64::from(sequence) * 100,
		digest: [sequence; 32],
	}
}

fn live(stage: u8) -> LiveBinding {
	let scope = ScopeBinding {
		subject: [stage; 32],
		namespace: [stage; 32],
		stage: identity(u64::from(stage)),
		base_grant: [3; 32],
		qualification: [4; 32],
		approval: Approval {
			digest: [5; 32],
			deadline: NonZeroU64::new(100).unwrap(),
		},
	};
	LiveBinding {
		scope,
		lease: [stage; 32],
		base_grant: Some(scope.base_grant),
		approval: Some(scope.approval),
		now: Some(99),
		head: head(2),
	}
}

fn namespace(
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

fn stage_alias(live: LiveBinding, links: u64) -> NameObservation {
	Held(HeldFile {
		identity: live.scope.stage,
		links,
	})
}

fn incumbent() -> NameObservation {
	Held(HeldFile {
		identity: identity(9),
		links: 1,
	})
}

fn witnessed_stage(live: LiveBinding) -> NamespaceObservation {
	let alias = stage_alias(live, 2);
	namespace(live, alias, alias, Absent)
}

fn witnessed_target(live: LiveBinding) -> NamespaceObservation {
	let alias = stage_alias(live, 2);
	namespace(live, Absent, alias, alias)
}

fn submit_witness(mut live: LiveBinding) -> (Publication, WitnessSubmission, LiveBinding) {
	let names = namespace(live, stage_alias(live, 1), Absent, Absent);
	let mut publication = Publication::begin(live, names, CaptureBoundary::ClosedAndSynced)
		.expect("closed capture should establish the original live state");
	live.head = head(3);
	publication
		.witness_intent(live)
		.expect("the confirmed intent immediately follows closed capture");
	let submission = publication
		.submit_witness(live, names)
		.expect("the stage is held and the protected witness name is free");
	(publication, submission, live)
}

fn submit_rename(live: LiveBinding) -> (Publication, RenameSubmission, LiveBinding) {
	let (mut publication, submission, mut live) = submit_witness(live);
	let names = witnessed_stage(live);
	assert_eq!(
		publication.observe_witness(submission, live, names, NativeWitnessOutcome::Linked),
		Ok(WitnessObservation::Linked)
	);
	live.head = head(4);
	publication
		.seal_witness(live, names, WitnessBarriers::BothConfirmed)
		.expect("both barriers confirmed on the witnessed stage");
	live.head = head(7);
	publication
		.rename_intent(live, names, head(5), head(6))
		.expect("verification and metadata immediately precede durable intent");
	let submission = publication
		.submit_rename(live, names)
		.expect("the exact two-link stage is held and the target is absent");
	(publication, submission, live)
}

#[test]
fn witness_classification_preserves_actual_return_and_requires_held_aliases() {
	use NativeWitnessOutcome::{Linked, Refused};
	let original = live(1);
	let linked = witnessed_stage(original);
	let three_links = stage_alias(original, 3);
	for (case, names, outcome, expected) in [
		(
			"a late distinct target does not invalidate the witness link",
			NamespaceObservation {
				target: incumbent(),
				..linked
			},
			Linked,
			WitnessObservation::Linked,
		),
		(
			"native refusal before creating the witness",
			namespace(original, stage_alias(original, 1), Absent, Absent),
			Refused,
			WitnessObservation::Reconcile(Refused),
		),
		(
			"lost native return despite visible aliases",
			linked,
			NativeWitnessOutcome::Uncertain,
			WitnessObservation::Reconcile(NativeWitnessOutcome::Uncertain),
		),
		(
			"unconfirmed witness name",
			NamespaceObservation {
				witness: Uncertain,
				..linked
			},
			Linked,
			WitnessObservation::Reconcile(Linked),
		),
		(
			"a third alias defeats the two-link check",
			namespace(original, three_links, three_links, Absent),
			Linked,
			WitnessObservation::Reconcile(Linked),
		),
	] {
		let (mut publication, submission, live) = submit_witness(original);
		assert_eq!(
			publication.observe_witness(submission, live, names, outcome),
			Ok(expected),
			"{case}"
		);
		assert_eq!(
			publication.submit_witness(live, names),
			Err(Refusal::Order),
			"{case} permits no repeated link"
		);
	}
}

#[test]
fn rename_classification_distinguishes_the_native_return_from_current_names() {
	use NativeRenameOutcome::{Conflict, Success};
	let original = live(1);
	let published = witnessed_target(original);
	let staged = witnessed_stage(original);
	let renames_to_reconcile = [
		(
			"the successful rename's target was removed before recheck",
			namespace(original, Absent, stage_alias(original, 1), Absent),
			Success,
		),
		(
			"the successful rename's target was replaced with another inode",
			namespace(original, Absent, stage_alias(original, 1), incumbent()),
			Success,
		),
		(
			"an unrelated object has appeared at the old private name",
			NamespaceObservation {
				stage: incumbent(),
				..published
			},
			Success,
		),
		(
			"the published inode's witness name is unconfirmed",
			NamespaceObservation {
				witness: Uncertain,
				..published
			},
			Success,
		),
		(
			"reply lost despite a visible public alias",
			published,
			NativeRenameOutcome::Uncertain,
		),
		(
			"the conflicting incumbent disappeared before recheck",
			staged,
			Conflict,
		),
		(
			"the conflicting name cannot be confirmed as a held regular file",
			NamespaceObservation {
				target: Uncertain,
				..staged
			},
			Conflict,
		),
		(
			"native conflict with a regular incumbent but unconfirmed stage custody",
			NamespaceObservation {
				stage: Uncertain,
				target: incumbent(),
				..staged
			},
			Conflict,
		),
	];
	for (case, names, outcome) in renames_to_reconcile {
		let (mut publication, submission, live) = submit_rename(original);
		assert_eq!(
			publication.observe_submission(submission, live, names, outcome),
			Ok(SubmissionObservation::Reconcile(outcome)),
			"{case}"
		);
		assert_eq!(
			publication.submit_rename(live, staged),
			Err(Refusal::Order),
			"{case} permits no repeated rename"
		);
	}
}

#[test]
fn witness_return_requires_original_live_binding_and_protected_names() {
	let original = live(1);
	let mut changed_subject = original.scope;
	changed_subject.subject = [2; 32];
	let changed_digest = Head {
		digest: [2; 32],
		..head(3)
	};
	let bound = LiveBinding {
		head: head(3),
		..original
	};
	let names = witnessed_stage(bound);
	let other_lease = LiveBinding {
		lease: [2; 32],
		..bound
	};
	let other_names = NamespaceObservation {
		lease: other_lease.lease,
		..names
	};
	for (case, live, observed) in [
		("new lease", other_lease, other_names),
		(
			"changed subject",
			LiveBinding {
				scope: changed_subject,
				..bound
			},
			names,
		),
		(
			"different digest at the same journal offset",
			LiveBinding {
				head: changed_digest,
				..bound
			},
			names,
		),
		("lease mismatch on name observations", bound, other_names),
		(
			"namespace mismatch on name observations",
			bound,
			NamespaceObservation {
				namespace: [2; 32],
				..names
			},
		),
		(
			"lost namespace protection",
			bound,
			NamespaceObservation {
				protected: false,
				..names
			},
		),
	] {
		let (mut publication, submission, _) = submit_witness(original);
		assert_eq!(
			publication.observe_witness(submission, live, observed, NativeWitnessOutcome::Linked),
			Ok(WitnessObservation::Reconcile(NativeWitnessOutcome::Linked)),
			"{case}"
		);
	}
}

#[test]
fn rename_keeps_confirmed_conflict_after_current_approval_becomes_unavailable() {
	let (mut publication, submission, mut live) = submit_rename(live(1));
	live.approval = None;
	let names = NamespaceObservation {
		target: Held(HeldFile {
			identity: identity(9),
			links: 2,
		}),
		..witnessed_stage(live)
	};
	assert_eq!(
		publication.observe_submission(submission, live, names, NativeRenameOutcome::Conflict),
		Ok(SubmissionObservation::Conflict)
	);
}

#[test]
fn crossed_submissions_are_refused_without_consuming_the_matched_return() {
	let (mut witness, linked, live_witness) = submit_witness(live(1));
	let (_foreign, foreign_link, _) = submit_witness(live(2));
	let names = witnessed_stage(live_witness);
	assert_eq!(
		witness.observe_witness(
			foreign_link,
			live_witness,
			names,
			NativeWitnessOutcome::Linked
		),
		Err(Refusal::Binding)
	);
	assert_eq!(
		witness.observe_witness(linked, live_witness, names, NativeWitnessOutcome::Linked),
		Ok(WitnessObservation::Linked)
	);

	let (mut rename, submitted, live_rename) = submit_rename(live(3));
	let (_foreign, foreign_rename, _) = submit_rename(live(4));
	let names = witnessed_target(live_rename);
	assert_eq!(
		rename.observe_submission(
			foreign_rename,
			live_rename,
			names,
			NativeRenameOutcome::Success
		),
		Err(Refusal::Binding)
	);
	assert_eq!(
		rename.observe_submission(submitted, live_rename, names, NativeRenameOutcome::Success),
		Ok(SubmissionObservation::Published)
	);
}
