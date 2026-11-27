use super::{
	Approval, CaptureBoundary, FileIdentity, Head, LinkedPublication, LiveBinding, NonZeroU64,
	Publication, Refusal, ScopeBinding, WitnessModel,
};

fn head(sequence: u8) -> Head {
	Head {
		digest: [sequence; 32],
		sequence: u64::from(sequence),
		end: 256 * u64::from(sequence),
	}
}

fn live(model: &WitnessModel, sequence: u8) -> LiveBinding {
	LiveBinding {
		base_grant: Some(model.scope.base_grant),
		approval: Some(model.scope.approval),
		now: Some(8),
		..model.observation(head(sequence))
	}
}

fn original_pass() -> LinkedPublication {
	let model = WitnessModel {
		lease: [7; 32],
		scope: ScopeBinding {
			subject: [1; 32],
			namespace: [2; 32],
			stage: FileIdentity {
				mount: NonZeroU64::new(3).unwrap(),
				device: 4,
				inode: NonZeroU64::new(5).unwrap(),
			},
			base_grant: [5; 32],
			qualification: [6; 32],
			approval: Approval {
				digest: [9; 32],
				deadline: NonZeroU64::new(10).unwrap(),
			},
		},
	};
	let mut state = Publication::begin(
		live(&model, 1),
		model.names(false),
		CaptureBoundary::ClosedAndSynced,
	)
	.unwrap();
	state.witness_intent(live(&model, 2)).unwrap();
	let submission = state
		.submit_witness(live(&model, 2), model.names(false))
		.unwrap();
	let mut linked = model.linked(state, submission, head(2)).unwrap();
	linked.seal(head(3), Some(8)).unwrap();
	linked.verified(head(4));
	linked.metadata(head(5));
	linked
}

#[test]
fn live_application_submission_refuses_displaced_scope_stale_stage_or_expired_approval() {
	let mut original = original_pass();
	let current = live(&original.model, 6);
	let mut foreign_subject = current;
	foreign_subject.scope.subject = [21; 32];
	let mut foreign_namespace = current;
	foreign_namespace.scope.namespace = [22; 32];
	let mut foreign_mount = current;
	foreign_mount.scope.stage.mount = NonZeroU64::new(8).unwrap();
	for refused in [
		foreign_subject,
		foreign_namespace,
		foreign_mount,
		LiveBinding {
			lease: [19; 32],
			..current
		},
		LiveBinding {
			now: Some(10),
			..current
		},
		LiveBinding {
			base_grant: None,
			..current
		},
		LiveBinding {
			head: head(7),
			..current
		},
	] {
		assert!(matches!(
			original.authorize_rename(refused),
			Err(Refusal::Binding)
		));
	}
	let submission = original.authorize_rename(current).unwrap();
	assert_eq!(submission.binding(), (head(6), original.model.scope));
	assert!(matches!(
		original.authorize_rename(current),
		Err(Refusal::Order)
	));
}

#[test]
fn live_application_submission_requires_both_exact_prepublication_heads() {
	let mut linked = original_pass();
	let current = live(&linked.model, 6);
	linked.metadata = None;
	assert!(matches!(
		linked.authorize_rename(current),
		Err(Refusal::Evidence)
	));
	linked.metadata(head(5));
	linked.verified(head(5));
	assert!(matches!(
		linked.authorize_rename(current),
		Err(Refusal::Binding)
	));
}
