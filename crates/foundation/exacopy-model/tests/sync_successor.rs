//! Replay approved one-subject successor evidence and independent counterexamples.

use core::num::NonZeroU64;

use exacopy_core::{EntryId, JobId, RunEpoch, StageId, UnixComponent};
use exacopy_model::sync_genesis::{
	FileId, GenesisRefusal, Measurement, ObservationStamp, RecheckedObservation, RootId, Scope,
	Selection,
};
use exacopy_model::sync_successor::{
	ApprovedCreate, DurableIntent, EffectOutcome, PostReceiptMeasurement, Postconditions,
	Predecessor, SuccessorBlock, SuccessorDecision, SuccessorEvidence, VerifiedReceipt, assess,
};
use exacopy_model::{CopyBinding, RegularFileEvidence, SyncSide};

const CONTENT: RegularFileEvidence = RegularFileEvidence {
	byte_len: 19,
	content_digest: [0x71; 32],
	required_metadata_digest: [0x72; 32],
};
const SOURCE: FileId = FileId([0x51; 32]);
const DESTINATION: FileId = FileId([0x52; 32]);

fn number(value: u64) -> NonZeroU64 {
	NonZeroU64::new(value).expect("fixture has nonzero generation and sequence numbers")
}

fn component(bytes: &'static [u8]) -> UnixComponent<'static> {
	UnixComponent::new(bytes).expect("fixture basename is a single raw component")
}

fn copy_binding(epoch: u64) -> CopyBinding {
	let job = JobId::try_from_bytes([
		0x01, 0x8d, 0x45, 0xbe, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01,
	])
	.expect("fixture job carries the UUIDv7 version and RFC variant");
	CopyBinding::new(
		job,
		EntryId::new(17),
		RunEpoch::new(epoch),
		StageId::from_bytes([1; 16]),
	)
}

struct Subject {
	approval: ApprovedCreate<'static>,
	current: Option<Predecessor<'static>>,
	intent: Option<DurableIntent<'static>>,
	receipt: VerifiedReceipt<'static>,
	observed_receipt: Option<[u8; 32]>,
	postconditions: Postconditions<'static>,
}

impl Subject {
	fn complete(from: SyncSide, generation: u64) -> Self {
		let roots = [RootId([0x11; 32]), RootId([0x12; 32])];
		let scope = Scope {
			selection: [0x21; 32],
			name: component(b"subject-\xff"),
			policy: [0x22; 32],
		};
		let predecessor = Predecessor {
			generation: number(generation),
			digest: [0x31; 32],
			roots,
			scope,
		};
		let approval = ApprovedCreate {
			predecessor,
			parent_plan_digest: [0x41; 32],
			action_id: [0x42; 16],
			child_plan_digest: [0x43; 32],
			from,
			source_file: SOURCE,
			source_evidence: CONTENT,
		};
		let intent = DurableIntent {
			approved: approval,
			copy: copy_binding(2),
			digest: [0x61; 32],
		};
		let receipt = VerifiedReceipt {
			intent,
			published_file: DESTINATION,
			evidence: CONTENT,
			digest: [0x62; 32],
		};
		let selection = Selection {
			roots,
			scope,
			scan: number(29),
		};
		let (left, right) = match from {
			SyncSide::Left => (SOURCE, DESTINATION),
			SyncSide::Right => (DESTINATION, SOURCE),
		};
		let [left_read, right_read] =
			[(0, left, 11, 13), (1, right, 10, 12)].map(|(side, file, start, end)| {
				PostReceiptMeasurement {
					started_at: number(start),
					measurement: Measurement {
						observation: ObservationStamp {
							root: roots[side],
							scope,
							scan: selection.scan,
							file,
							stability: [0x81; 32],
						},
						completed_at: number(end),
						evidence: CONTENT,
					},
				}
			});
		Self {
			approval,
			current: Some(predecessor),
			intent: Some(intent),
			observed_receipt: Some(receipt.digest),
			postconditions: Postconditions {
				selection,
				receipt_digest: receipt.digest,
				receipt_validated_at: number(9),
				measurements: [Some(left_read), Some(right_read)],
				rechecked: [
					Some(RecheckedObservation {
						observation: left_read.measurement.observation,
						observed_at: number(15),
					}),
					Some(RecheckedObservation {
						observation: right_read.measurement.observation,
						observed_at: number(14),
					}),
				],
			},
			receipt,
		}
	}

	fn decision(self) -> SuccessorDecision {
		self.decision_for(|receipt| EffectOutcome::Verified(receipt))
	}

	fn decision_for(
		self,
		outcome: impl for<'receipt> FnOnce(
			&'receipt VerifiedReceipt<'static>,
		) -> EffectOutcome<'receipt, 'static>,
	) -> SuccessorDecision {
		assess(
			&self.approval,
			&SuccessorEvidence {
				current: self.current,
				intent: self.intent,
				outcome: outcome(&self.receipt),
				observed_receipt: self.observed_receipt,
				postconditions: self.postconditions,
			},
		)
	}

	fn reconcile(self, reason: SuccessorBlock) {
		assert_eq!(self.decision(), SuccessorDecision::Reconcile(reason));
	}
}

#[test]
fn exact_create_new_evidence_can_support_the_immediate_successor_in_either_direction() {
	for from in [SyncSide::Left, SyncSide::Right] {
		assert_eq!(
			Subject::complete(from, 6).decision(),
			SuccessorDecision::Eligible {
				generation: number(7),
			},
			"source side {from:?}",
		);
	}
	Subject::complete(SyncSide::Left, u64::MAX).reconcile(SuccessorBlock::GenerationExhausted);
}

#[test]
fn complete_effect_cannot_advance_an_unselected_or_superseded_predecessor() {
	let mut subject = Subject::complete(SyncSide::Left, 6);
	subject.current = None;
	subject.reconcile(SuccessorBlock::Predecessor);

	let mut subject = Subject::complete(SyncSide::Left, 6);
	subject.current = Some(Predecessor {
		generation: number(7),
		digest: [0xa1; 32],
		..subject.approval.predecessor
	});
	subject.reconcile(SuccessorBlock::Predecessor);

	let mut subject = Subject::complete(SyncSide::Left, 6);
	subject.current = Some(Predecessor {
		digest: [0xa2; 32],
		..subject.approval.predecessor
	});
	subject.reconcile(SuccessorBlock::Predecessor);
}

#[test]
fn observations_cannot_substitute_for_durable_intent_or_a_verified_effect() {
	let mut subject = Subject::complete(SyncSide::Left, 6);
	subject.intent = None;
	subject.reconcile(SuccessorBlock::Intent);

	let mut subject = Subject::complete(SyncSide::Left, 6);
	let mut intent = subject.intent.expect("fixture provides durable intent");
	intent.approved.child_plan_digest = [0xa3; 32];
	subject.intent = Some(intent);
	subject.reconcile(SuccessorBlock::Intent);

	let mut subject = Subject::complete(SyncSide::Left, 6);
	let mut intent = subject.intent.expect("fixture provides durable intent");
	intent.approved.parent_plan_digest = [0xaa; 32];
	subject.intent = Some(intent);
	subject.reconcile(SuccessorBlock::Intent);

	let mut subject = Subject::complete(SyncSide::Left, 6);
	let mut intent = subject.intent.expect("fixture provides durable intent");
	intent.approved.action_id = [0xab; 16];
	subject.intent = Some(intent);
	subject.reconcile(SuccessorBlock::Intent);

	assert_eq!(
		Subject::complete(SyncSide::Left, 6).decision_for(|_| EffectOutcome::Missing),
		SuccessorDecision::Reconcile(SuccessorBlock::MissingReceipt),
	);
	assert_eq!(
		Subject::complete(SyncSide::Left, 6).decision_for(|_| EffectOutcome::Uncertain),
		SuccessorDecision::Reconcile(SuccessorBlock::UncertainEffect),
	);
}

#[test]
fn authentic_receipt_evidence_needs_the_exact_intent_and_approved_content() {
	let mut subject = Subject::complete(SyncSide::Left, 6);
	subject.receipt.intent.copy = copy_binding(1);
	subject.reconcile(SuccessorBlock::ReceiptBinding);

	let mut subject = Subject::complete(SyncSide::Left, 6);
	subject.receipt.intent.digest = [0xa4; 32];
	subject.reconcile(SuccessorBlock::ReceiptBinding);

	let mut subject = Subject::complete(SyncSide::Left, 6);
	subject.receipt.intent.approved.action_id = [0xab; 16];
	subject.reconcile(SuccessorBlock::ReceiptBinding);

	let mut subject = Subject::complete(SyncSide::Left, 6);
	subject.receipt.evidence.required_metadata_digest = [0xa5; 32];
	subject.reconcile(SuccessorBlock::ReceiptBinding);

	let mut subject = Subject::complete(SyncSide::Left, 6);
	subject.receipt.published_file = SOURCE;
	subject.reconcile(SuccessorBlock::ReceiptBinding);
}

#[test]
fn a_verified_receipt_must_match_the_durable_action_observation() {
	for observed_receipt in [None, Some([0xac; 32])] {
		let mut subject = Subject::complete(SyncSide::Left, 6);
		subject.observed_receipt = observed_receipt;
		subject.reconcile(SuccessorBlock::ReceiptCommitment);
	}
}

#[test]
fn even_complete_matched_observations_need_the_exact_receipt_and_scope() {
	let mut subject = Subject::complete(SyncSide::Left, 6);
	subject.postconditions.receipt_digest = [0xa6; 32];
	subject.reconcile(SuccessorBlock::PostconditionReceipt);

	let mut subject = Subject::complete(SyncSide::Left, 6);
	let postconditions = &mut subject.postconditions;
	postconditions.selection.scope.name = component(b"subject-\xfe");
	for read in postconditions.measurements.iter_mut().flatten() {
		read.measurement.observation.scope = postconditions.selection.scope;
	}
	for recheck in postconditions.rechecked.iter_mut().flatten() {
		recheck.observation.scope = postconditions.selection.scope;
	}
	subject.reconcile(SuccessorBlock::PostconditionSelection);

	let mut subject = Subject::complete(SyncSide::Left, 6);
	let postconditions = &mut subject.postconditions;
	let other_root = RootId([0xa9; 32]);
	postconditions.selection.roots[1] = other_root;
	postconditions.measurements[1]
		.as_mut()
		.expect("fixture provides the right read")
		.measurement
		.observation
		.root = other_root;
	postconditions.rechecked[1]
		.as_mut()
		.expect("fixture provides the right recheck")
		.observation
		.root = other_root;
	subject.reconcile(SuccessorBlock::PostconditionSelection);
}

#[test]
fn neither_side_can_supply_missing_or_pre_receipt_evidence_for_the_other() {
	for side in [0, 1] {
		let mut subject = Subject::complete(SyncSide::Left, 6);
		subject.postconditions.measurements[side] = None;
		subject.reconcile(SuccessorBlock::Postconditions(
			GenesisRefusal::MissingMeasurement,
		));

		let mut subject = Subject::complete(SyncSide::Left, 6);
		subject.postconditions.rechecked[side] = None;
		subject.reconcile(SuccessorBlock::Postconditions(GenesisRefusal::StaleRecheck));
	}

	for side in [0, 1] {
		let mut subject = Subject::complete(SyncSide::Left, 6);
		subject.postconditions.measurements[side]
			.as_mut()
			.expect("fixture provides both reads")
			.measurement
			.completed_at = subject.postconditions.receipt_validated_at;
		subject.reconcile(SuccessorBlock::StalePostconditions);
	}
}

#[test]
fn completion_after_receipt_validation_cannot_hide_an_earlier_or_invalid_start() {
	for (side, completed_at) in [(0, 13), (1, 12)] {
		for start in [8, 9, completed_at, completed_at + 1] {
			let mut subject = Subject::complete(SyncSide::Left, 6);
			subject.postconditions.measurements[side]
				.as_mut()
				.expect("fixture provides both reads")
				.started_at = number(start);
			subject.reconcile(SuccessorBlock::StalePostconditions);
		}
	}
}

#[test]
fn a_late_recheck_must_confirm_that_the_observation_stayed_stable() {
	let mut subject = Subject::complete(SyncSide::Left, 6);
	subject.postconditions.rechecked[1]
		.as_mut()
		.expect("fixture provides the right recheck")
		.observation
		.stability = [0xad; 32];
	subject.reconcile(SuccessorBlock::Postconditions(GenesisRefusal::StaleRecheck));
}

#[test]
fn equal_streams_cannot_hide_replacement_of_either_confirmed_file() {
	for side in [0, 1] {
		let mut subject = Subject::complete(SyncSide::Right, 6);
		let postconditions = &mut subject.postconditions;
		postconditions.measurements[side]
			.as_mut()
			.expect("fixture provides both reads")
			.measurement
			.observation
			.file = FileId([0xa7; 32]);
		postconditions.rechecked[side]
			.as_mut()
			.expect("fixture provides both rechecks")
			.observation
			.file = FileId([0xa7; 32]);
		subject.reconcile(SuccessorBlock::PostconditionBinding);
	}

	let mut subject = Subject::complete(SyncSide::Right, 6);
	for read in subject.postconditions.measurements.iter_mut().flatten() {
		read.measurement.evidence.content_digest = [0xa8; 32];
	}
	subject.reconcile(SuccessorBlock::PostconditionBinding);
}

#[test]
fn earlier_eligibility_cannot_survive_reassessment_after_the_current_head_moves() {
	let Subject {
		approval,
		current,
		intent,
		receipt,
		observed_receipt,
		postconditions,
	} = Subject::complete(SyncSide::Left, 6);
	let mut evidence = SuccessorEvidence {
		current,
		intent,
		outcome: EffectOutcome::Verified(&receipt),
		observed_receipt,
		postconditions,
	};
	assert_eq!(
		assess(&approval, &evidence),
		SuccessorDecision::Eligible {
			generation: number(7),
		},
	);
	evidence.current = Some(Predecessor {
		generation: number(7),
		digest: [0xae; 32],
		..approval.predecessor
	});
	assert_eq!(
		assess(&approval, &evidence),
		SuccessorDecision::Reconcile(SuccessorBlock::Predecessor),
	);
}
