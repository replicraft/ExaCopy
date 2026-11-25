use exacopy_journal::{
	NamespaceObservation, PublishedRecoveryEvidence, RecoveryDecision, RecoveryStartEvidence,
	RecoveryStarted, StreamDigest,
};

use super::*;

struct History {
	bytes: Vec<u8>,
	head: ChainHead,
	verification: ChainHead,
	metadata: ChainHead,
	intent: ChainHead,
	context: PublishIntentContext,
	stream: StreamEvidence,
	owner: OwnerDigest,
}

impl History {
	fn new(fixture: &Fixture, records: Records, records_to_keep: usize) -> Self {
		let context = records.intent.context;
		let stream = records.verification.stage();
		let (bytes, boundaries) = records.bytes(records_to_keep);
		Self {
			bytes,
			head: boundaries[records_to_keep].head,
			verification: boundaries[4].head,
			metadata: boundaries[5].head,
			intent: boundaries[6].head,
			context,
			stream,
			owner: fixture.owner.digest(),
		}
	}

	fn append(&mut self, kind: FrameKind, payload: &[u8]) -> ChainHead {
		self.head = FrameWriter::new(&mut self.bytes, self.head)
			.append(kind, payload)
			.unwrap();
		self.head
	}

	fn recovery_context(&self, epoch: u64) -> JournalContext {
		JournalContext {
			job: self.context.job,
			plan_digest: self.context.plan_digest,
			epoch: JournalEpoch::new(epoch),
		}
	}

	fn start_evidence(&self) -> RecoveryStartEvidence {
		RecoveryStartEvidence {
			intent: self.intent,
			preceding: self.head,
			authorization: self.owner,
		}
	}

	fn start(&mut self, prior_epoch: u64) -> ChainHead {
		let started = RecoveryStarted::new(
			self.recovery_context(prior_epoch + 1),
			self.context.entry,
			JournalEpoch::new(prior_epoch),
			self.start_evidence(),
		)
		.unwrap();
		self.append(FrameKind::RecoveryStarted, &started.encode())
	}

	fn decision_evidence(&self) -> PublishedRecoveryEvidence {
		PublishedRecoveryEvidence {
			target: STAGE,
			destination_directory: LinuxFileIdentity::new(STAGE.device(), 13),
			stage_directory: STAGE_DIRECTORY,
			verification: self.verification,
			metadata: self.metadata,
			stream: self.stream,
		}
	}

	fn decide(&mut self, epoch: u64, evidence: PublishedRecoveryEvidence) -> ChainHead {
		let decision = RecoveryDecision::new(
			self.recovery_context(epoch),
			self.context.entry,
			self.head,
			evidence,
		)
		.unwrap();
		self.append(FrameKind::RecoveryDecision, &decision.encode())
	}

	fn observe(&mut self) -> ChainHead {
		let observed = PublishObserved::new(
			self.context,
			self.intent,
			PublicationOutcome::Published { target: STAGE },
		)
		.unwrap();
		self.append(FrameKind::PublishObserved, &observed.encode())
	}

	fn finish_barriers(&mut self, observed: ChainHead, stage: LinuxFileIdentity) -> ChainHead {
		let durability = DurabilityRecorded::new(
			self.context,
			observed,
			LinuxPublicationBarriers {
				metadata: self.metadata,
				stage_directory: stage,
				destination_directory: self.decision_evidence().destination_directory,
			},
		)
		.unwrap();
		self.append(FrameKind::DurabilityRecorded, &durability.encode())
	}

	fn commit_receipt(&mut self, durability: ChainHead) {
		let receipt =
			ReceiptCommitted::new(self.context, ReceiptDigest::from_bytes([8; 32]), durability)
				.unwrap();
		self.append(FrameKind::ReceiptCommitted, &receipt.encode());
	}
}

#[test]
fn a_fresh_generation_can_replace_an_interrupted_attempt_and_finish_an_unobserved_rename() {
	let fixture = Fixture::new();
	let mut log = History::new(&fixture, fixture.records(), 6);

	let interrupted = log.start(3);
	let prefix = fixture.replay(&log.bytes).unwrap();
	assert_eq!(prefix.latest_epoch, JournalEpoch::new(4));
	assert_eq!(prefix.boundary.head, interrupted);
	assert_eq!(prefix.observation, None);

	let restarted = log.start(4);
	let decision = log.decide(5, log.decision_evidence());
	let decision_end = log.bytes.len();
	let observed = log.observe();
	for cut in decision_end + 1..log.bytes.len() {
		let summary = fixture.replay(&log.bytes[..cut]).unwrap();
		assert_eq!(summary.latest_epoch, JournalEpoch::new(5));
		assert_eq!(summary.boundary.head, decision);
		assert!(matches!(summary.tail, JournalTail::Torn { .. }));
		assert_eq!(summary.observation_head, None);
	}
	assert!(decision.sequence() > restarted.sequence());

	let barriers = log.finish_barriers(observed, STAGE_DIRECTORY);
	log.commit_receipt(barriers);
	let summary = fixture.replay(&log.bytes).unwrap();
	assert_eq!(summary.latest_epoch, JournalEpoch::new(5));
	assert_eq!(summary.verification_head, Some(log.verification));
	assert_eq!(summary.metadata_head, Some(log.metadata));
	assert_eq!(summary.intent_head, Some(log.intent));
	assert_eq!(summary.observation_head, Some(observed));
	assert_eq!(summary.durability_head, Some(barriers));
	assert_eq!(summary.recovery_stage_directory, Some(STAGE_DIRECTORY));
	assert_eq!(summary.receipt.unwrap().context(), log.context);
	assert_eq!(summary.receipt.unwrap().durability(), barriers);

	let done = log.bytes.len();
	log.start(5);
	assert!(matches!(
		fixture.replay(&log.bytes[..done + 1]),
		Err(JournalReplayError::TrailingAfterReceipt),
	));
	assert!(matches!(
		fixture.replay(&log.bytes),
		Err(JournalReplayError::UnexpectedRecord {
			expected: None,
			found: FrameKind::RecoveryStarted,
		})
	));
}

#[test]
fn only_a_recovery_decision_can_replace_an_uncertain_observation() {
	let fixture = Fixture::new();
	let mut records = fixture.records();
	records.outcome = PublicationOutcome::Uncertain {
		target: NamespaceObservation::Unobserved,
		stage_name: NamespaceObservation::Unobserved,
	};

	let mut log = History::new(&fixture, records, 7);
	let old_head = log.head;
	let original = fixture.replay(&log.bytes).unwrap();
	assert_eq!(original.observation_head, Some(old_head));
	let boundary = log.bytes.len();
	log.observe();
	assert_binding(&fixture, &log.bytes, FrameKind::PublishObserved);
	log.bytes.truncate(boundary);
	log.head = old_head;

	log.start(3);
	let boundary = log.bytes.len();
	let started = log.head;
	log.observe();
	assert_binding(&fixture, &log.bytes, FrameKind::PublishObserved);
	log.bytes.truncate(boundary);
	log.head = started;

	log.decide(4, log.decision_evidence());
	let current = log.observe();
	let summary = fixture.replay(&log.bytes).unwrap();
	assert_eq!(summary.observation_head, Some(current));
	assert_eq!(
		summary.observation.unwrap().outcome(),
		PublicationOutcome::Published { target: STAGE }
	);
}

#[test]
fn recovery_preserves_an_existing_durability_head_when_resuming_a_receipt() {
	let fixture = Fixture::new();
	let mut log = History::new(&fixture, fixture.records(), 8);
	let durability = log.head;
	log.start(3);
	log.decide(4, log.decision_evidence());
	let decided = fixture.replay(&log.bytes).unwrap();
	assert_ne!(decided.boundary.head, durability);
	assert_eq!(decided.durability_head, Some(durability));
	log.commit_receipt(durability);
	let finished = fixture.replay(&log.bytes).unwrap();
	assert_eq!(finished.receipt.unwrap().durability(), durability);
}

#[test]
fn recovery_requires_original_intent_and_refuses_a_confirmed_no_effect_outcome() {
	let fixture = Fixture::new();
	let (mut bytes, boundaries) = fixture.records().bytes(5);
	FrameWriter::new(&mut bytes, boundaries[5].head)
		.append(FrameKind::RecoveryStarted, &[])
		.unwrap();
	assert!(matches!(
		fixture.replay(&bytes),
		Err(JournalReplayError::UnexpectedRecord {
			expected: Some(FrameKind::PublishIntent),
			found: FrameKind::RecoveryStarted,
		})
	));

	let mut records = fixture.records();
	records.outcome = PublicationOutcome::NotPerformed {
		stage: STAGE,
		target: None,
	};
	let mut log = History::new(&fixture, records, 7);
	log.start(3);
	assert_binding(&fixture, &log.bytes, FrameKind::RecoveryStarted);
}

#[test]
fn stale_wrong_owner_and_wrong_predecessor_starts_are_refused() {
	let fixture = Fixture::new();
	for variant in 0..4 {
		let mut log = History::new(&fixture, fixture.records(), 6);
		log.start(3);
		let mut evidence = log.start_evidence();
		let prior_epoch = match variant {
			0 => 3,
			1 => {
				evidence.authorization = OwnerDigest::from_bytes([77; 32]);
				4
			}
			2 => {
				evidence.preceding = log.intent;
				4
			}
			3 => {
				evidence.intent = ChainHead::after(log.intent.sequence(), [66; 32]).unwrap();
				4
			}
			_ => unreachable!(),
		};
		let forged = RecoveryStarted::new(
			log.recovery_context(prior_epoch + 1),
			log.context.entry,
			JournalEpoch::new(prior_epoch),
			evidence,
		)
		.unwrap();
		log.append(FrameKind::RecoveryStarted, &forged.encode());
		if variant == 0 {
			assert_binding(&fixture, &log.bytes, FrameKind::RecoveryStarted);
		} else {
			assert!(matches!(
				fixture.replay(&log.bytes),
				Err(JournalReplayError::Recovery(_))
			));
		}
	}
}

#[test]
fn decision_must_follow_its_start_and_bind_verified_stream_and_metadata() {
	let fixture = Fixture::new();
	let mut log = History::new(&fixture, fixture.records(), 6);
	log.decide(4, log.decision_evidence());
	assert_binding(&fixture, &log.bytes, FrameKind::RecoveryDecision);

	for variant in 0..3 {
		let mut log = History::new(&fixture, fixture.records(), 6);
		log.start(3);
		let mut evidence = log.decision_evidence();
		let epoch = match variant {
			0 => 5,
			1 => {
				evidence.stream.digest = StreamDigest::from_bytes([9; 32]);
				4
			}
			2 => {
				evidence.metadata = ChainHead::after(log.metadata.sequence(), [6; 32]).unwrap();
				4
			}
			_ => unreachable!(),
		};
		log.decide(epoch, evidence);
		assert!(matches!(
			fixture.replay(&log.bytes),
			Err(JournalReplayError::Recovery(_))
		));
	}
}

#[test]
fn durable_suffix_must_match_recovery_directory_and_active_generation() {
	let fixture = Fixture::new();
	let mut log = History::new(&fixture, fixture.records(), 6);
	log.start(3);
	log.decide(4, log.decision_evidence());
	let observed = log.observe();
	log.finish_barriers(observed, LinuxFileIdentity::new(STAGE.device(), 50));
	assert_binding(&fixture, &log.bytes, FrameKind::DurabilityRecorded);

	let mut log = History::new(&fixture, fixture.records(), 8);
	let durability = log.head;
	log.start(3);
	let mut different_dir = log.decision_evidence();
	different_dir.stage_directory = LinuxFileIdentity::new(STAGE.device(), 50);
	log.decide(4, different_dir);
	assert!(matches!(
		fixture.replay(&log.bytes),
		Err(JournalReplayError::Recovery(_))
	));

	let mut log = History::new(&fixture, fixture.records(), 8);
	log.start(3);
	log.commit_receipt(durability);
	assert_binding(&fixture, &log.bytes, FrameKind::ReceiptCommitted);
}

fn assert_binding(fixture: &Fixture, bytes: &[u8], expected: FrameKind) {
	assert!(matches!(
		fixture.replay(bytes),
		Err(JournalReplayError::RecordBinding { kind }) if kind == expected
	));
}
