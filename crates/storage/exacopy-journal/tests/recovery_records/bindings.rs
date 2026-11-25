use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::{ChainHead, Frame, FrameKind, FrameReader, FrameWriter};
use exacopy_journal::{
	BasicMetadata, JournalContext, JournalEntryId, JournalEpoch, LinuxFileIdentity,
	MetadataRecorded, OwnerDigest, OwnerTimestamp, PlanDigest, PublicationPrimitive, PublishIntent,
	PublishIntentContext, PublishIntentTarget, PublishedRecoveryEvidence, RecoveryDecision,
	RecoveryDecisionFrames, RecoveryDirectories, RecoveryRecordError, RecoveryStartEvidence,
	RecoveryStarted, StreamDigest, StreamEvidence, StreamLength, VerificationDigest,
	VerificationRecorded,
};

use super::{
	ENTRY, FILE, OWNER, STAGE_DIR, TARGET_DIR, append, context, decision_evidence, path_frame,
	stream,
};

struct History {
	verification: Frame,
	metadata: Frame,
	intent: Frame,
	started: Frame,
	decision: Frame,
}

fn history(original_epoch: u64, prior_epoch: u64) -> History {
	let original = context(original_epoch);
	let timestamp = OwnerTimestamp::new(1, 2).expect("fixture metadata timestamp");
	let verification = VerificationRecorded::new(
		original,
		ENTRY,
		StreamEvidence {
			identity: LinuxFileIdentity::new(4, 10),
			..stream()
		},
		stream(),
	)
	.expect("matching stream measurements");
	let metadata = MetadataRecorded {
		context: original,
		entry: ENTRY,
		stage: FILE,
		metadata: BasicMetadata::new(0o600, 1000, 1000, timestamp, timestamp)
			.expect("fixture metadata"),
	};
	let intent = PublishIntent {
		context: PublishIntentContext {
			job: original.job,
			epoch: original.epoch,
			entry: ENTRY,
			effect_sequence: 1,
			plan_digest: original.plan_digest,
		},
		target: PublishIntentTarget {
			stage: FILE,
			parent: TARGET_DIR,
			component: UnixComponent::new(b"target").expect("fixture filename"),
			verification_digest: verification.record_digest(),
			primitive: PublicationPrimitive::LinuxRenameNoReplace,
		},
	};
	let mut writer = FrameWriter::new(Vec::new(), ChainHead::start());
	let verification = append(
		&mut writer,
		FrameKind::VerificationRecorded,
		&verification.encode(),
	);
	let metadata = append(&mut writer, FrameKind::MetadataRecorded, &metadata.encode());
	let intent = append(&mut writer, FrameKind::PublishIntent, &intent.encode());

	let mut preceding = intent;
	for epoch in original_epoch..prior_epoch {
		preceding = append_start(&mut writer, intent, preceding, epoch);
	}
	let recovery = context(prior_epoch + 1);
	let started = append_start(&mut writer, intent, preceding, prior_epoch);
	let decision = RecoveryDecision::new(
		recovery,
		ENTRY,
		started,
		PublishedRecoveryEvidence {
			verification,
			metadata,
			..decision_evidence()
		},
	)
	.expect("matching measurements and references");
	append(&mut writer, FrameKind::RecoveryDecision, &decision.encode());

	let bytes = writer.into_inner();
	let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());
	let mut next = || {
		reader
			.next_frame()
			.expect("read fixture chain")
			.expect("fixture frame")
	};
	let verification = next();
	let metadata = next();
	let intent = next();
	let mut start = next();
	while start.head() != started {
		start = next();
	}
	History {
		verification,
		metadata,
		intent,
		started: start,
		decision: next(),
	}
}

fn append_start(
	writer: &mut FrameWriter<Vec<u8>>,
	intent: ChainHead,
	preceding: ChainHead,
	prior: u64,
) -> ChainHead {
	let record = RecoveryStarted::new(
		context(prior + 1),
		ENTRY,
		JournalEpoch::new(prior),
		RecoveryStartEvidence {
			intent,
			preceding,
			authorization: OWNER,
		},
	)
	.expect("valid stand-alone start");
	append(writer, FrameKind::RecoveryStarted, &record.encode())
}

impl History {
	fn frames(&self) -> RecoveryDecisionFrames<'_> {
		RecoveryDecisionFrames {
			started: &self.started,
			intent: &self.intent,
			verification: &self.verification,
			metadata: &self.metadata,
		}
	}
}

fn directories() -> RecoveryDirectories {
	RecoveryDirectories {
		stage: STAGE_DIR,
		destination: TARGET_DIR,
	}
}

#[test]
fn decision_binds_original_evidence_after_multiple_recovery_generations() {
	for prior in [2, 4] {
		let history = history(2, prior);
		let start = RecoveryStarted::from_frame(&history.started).expect("exact predecessor");
		assert_eq!(start.prior_epoch(), JournalEpoch::new(prior));
		let intent = start
			.validate_intent(&history.intent, OWNER)
			.expect("matching intent");
		assert_eq!(intent.context.epoch, JournalEpoch::new(2));
		let decision = RecoveryDecision::from_frame(&history.decision).expect("exact predecessor");
		assert_eq!(decision.context().epoch, JournalEpoch::new(prior + 1));
		assert_eq!(
			decision.validate_evidence(history.frames(), OWNER, directories()),
			Ok(())
		);
	}
}

#[test]
fn intended_effect_cannot_come_from_a_future_epoch_or_different_context() {
	let history = history(3, 2);
	let start = RecoveryStarted::from_frame(&history.started).expect("valid start payload");
	assert_eq!(
		start.validate_intent(&history.intent, OWNER),
		Err(RecoveryRecordError::InvalidEpoch)
	);

	let history = self::history(2, 2);
	let start = RecoveryStarted::from_frame(&history.started).expect("valid start");
	let wrong_plan = JournalContext {
		plan_digest: PlanDigest::from_bytes([3; 32]),
		..context(3)
	};
	let wrong_entry = JournalEntryId::from_bytes([4; 16]);
	for (context, entry) in [(wrong_plan, ENTRY), (context(3), wrong_entry)] {
		let wrong = RecoveryStarted::new(context, entry, start.prior_epoch(), start.evidence())
			.expect("syntactically valid start");
		assert_eq!(
			wrong.validate_intent(&history.intent, OWNER),
			Err(RecoveryRecordError::BindingMismatch)
		);
	}
}

#[test]
fn decision_refuses_untrusted_owner_substituted_frames_or_directories() {
	let history = history(2, 2);
	let decision = RecoveryDecision::from_frame(&history.decision).expect("valid decision");
	let other = self::history(1, 1);
	for frames in [
		RecoveryDecisionFrames {
			started: &other.started,
			..history.frames()
		},
		RecoveryDecisionFrames {
			intent: &other.intent,
			..history.frames()
		},
		RecoveryDecisionFrames {
			verification: &other.verification,
			..history.frames()
		},
		RecoveryDecisionFrames {
			metadata: &other.metadata,
			..history.frames()
		},
	] {
		assert_eq!(
			decision.validate_evidence(frames, OWNER, directories()),
			Err(RecoveryRecordError::BindingMismatch)
		);
	}
	assert_eq!(
		decision.validate_evidence(
			history.frames(),
			OwnerDigest::from_bytes([5; 32]),
			directories()
		),
		Err(RecoveryRecordError::BindingMismatch)
	);
	assert_eq!(
		decision.validate_evidence(
			history.frames(),
			OWNER,
			RecoveryDirectories {
				stage: LinuxFileIdentity::new(5, 10),
				..directories()
			}
		),
		Err(RecoveryRecordError::BindingMismatch)
	);
}

#[test]
fn changed_stream_length_digest_identity_or_recovery_context_is_refused() {
	let history = history(2, 2);
	let decision = RecoveryDecision::from_frame(&history.decision).expect("valid decision");
	let original = decision.evidence();
	for stream in [
		StreamEvidence {
			digest: StreamDigest::from_bytes([0xaa; 32]),
			..original.stream
		},
		StreamEvidence {
			length: StreamLength::new(35).expect("fixture logical length"),
			..original.stream
		},
		StreamEvidence {
			identity: LinuxFileIdentity::new(5, 10),
			..original.stream
		},
	] {
		let mismatch = RecoveryDecision::new(
			decision.context(),
			ENTRY,
			decision.started(),
			PublishedRecoveryEvidence {
				target: stream.identity,
				stream,
				..original
			},
		)
		.expect("locally valid measurement");
		assert_eq!(
			mismatch.validate_evidence(history.frames(), OWNER, directories()),
			Err(RecoveryRecordError::BindingMismatch)
		);
	}
	let stale_decision = RecoveryDecision::new(context(2), ENTRY, decision.started(), original)
		.expect("syntactically valid decision");
	assert_eq!(
		stale_decision.validate_evidence(history.frames(), OWNER, directories()),
		Err(RecoveryRecordError::BindingMismatch)
	);
}

#[test]
fn original_verification_must_match_the_digest_in_the_publication_intent() {
	let history = history(2, 2);
	let existing = PublishIntent::from_frame(&history.intent).expect("supported intent");
	let altered = PublishIntent {
		target: PublishIntentTarget {
			verification_digest: VerificationDigest::from_bytes([0xdd; 32]),
			..existing.target
		},
		..existing
	};
	let intent = path_frame(
		history.metadata.head(),
		FrameKind::PublishIntent,
		&altered.encode(),
	);
	let start = RecoveryStarted::new(
		context(3),
		ENTRY,
		JournalEpoch::new(2),
		RecoveryStartEvidence {
			intent: intent.head(),
			preceding: intent.head(),
			authorization: OWNER,
		},
	)
	.expect("valid start payload");
	let started = path_frame(intent.head(), FrameKind::RecoveryStarted, &start.encode());
	let original = RecoveryDecision::from_frame(&history.decision).expect("valid decision");
	let altered = RecoveryDecision::new(context(3), ENTRY, started.head(), original.evidence())
		.expect("locally valid evidence");
	assert_eq!(
		altered.validate_evidence(
			RecoveryDecisionFrames {
				started: &started,
				intent: &intent,
				..history.frames()
			},
			OWNER,
			directories()
		),
		Err(RecoveryRecordError::BindingMismatch)
	);
}
