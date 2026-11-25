use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::{ChainHead, Frame, FrameKind};
use exacopy_journal::{
	BasicMetadata, JournalContext, JournalEpoch, LinuxFileIdentity, MetadataRecorded, OwnerDigest,
	OwnerTimestamp, PublicationPrimitive, PublishIntent, PublishIntentContext, PublishIntentTarget,
	RecoveryDecision, RecoveryDecisionFrames, RecoveryDirectories, RecoveryRecordError,
	RecoveryStartEvidence, RecoveryStarted, RetainedPublicationDecision,
	RetainedPublicationEvidence, StreamEvidence, VerificationDigest, VerificationRecorded,
};

use super::{
	DECISION_BODY, ENTRY, FILE, OWNER, RECOVERY_HEADER, STAGE_DIR, TARGET_DIR,
	check_invalid_encodings, context, golden, path_frame, reference, stream,
};

const SOURCE: LinuxFileIdentity = LinuxFileIdentity::new(4, 10);
const DIRECTORIES: RecoveryDirectories = RecoveryDirectories {
	stage: STAGE_DIR,
	destination: TARGET_DIR,
};
const RETAINED_BODY: &str = concat!(
	"a4000201a5",
	"00a40001014805000000000000000248090000000000000003f6",
	"01a40001014805000000000000000248080000000000000003f6",
	"02a40001014805000000000000000248070000000000000003f6",
	"0300040102a3",
	"00820958206666666666666666666666666666666666666666666666666666666666666666",
	"01820a58207777777777777777777777777777777777777777777777777777777777777777",
	"02820b58208888888888888888888888888888888888888888888888888888888888888888",
	"0302",
);

#[test]
fn retained_decision_matches_independent_cbor_and_rejects_the_existing_variant() {
	let record = RetainedPublicationDecision::new(
		context(3),
		ENTRY,
		reference(9, 0x66),
		RetainedPublicationEvidence {
			stage: FILE,
			directories: DIRECTORIES,
			verification: reference(10, 0x77),
			metadata: reference(11, 0x88),
		},
		2,
	)
	.expect("valid retained decision");
	let bytes = golden(RETAINED_BODY);
	assert_eq!(record.encode(), bytes);
	assert_eq!(RetainedPublicationDecision::decode(&bytes), Ok(record));
	assert_eq!(
		RecoveryDecision::decode(&bytes),
		Err(RecoveryRecordError::UnsupportedEvidence)
	);
	assert_eq!(
		RetainedPublicationDecision::decode(&golden(DECISION_BODY)),
		Err(RecoveryRecordError::UnsupportedEvidence)
	);
	check_invalid_encodings(RETAINED_BODY, |bytes| {
		RetainedPublicationDecision::decode(bytes).map(|_| ())
	});
}

#[test]
fn retained_decision_refuses_unknown_decision_states_and_zero_effect() {
	let canonical = golden(RETAINED_BODY);
	let header_end = RECOVERY_HEADER.len() / 2;
	let state_start = canonical
		.windows(6)
		.position(|window| window == [3, 0, 4, 1, 2, 0xa3])
		.expect("explicit states and following map");
	for index in [header_end + 2, state_start + 1, state_start + 3] {
		let mut unsupported = canonical.clone();
		unsupported[index] = 3;
		assert_eq!(
			RetainedPublicationDecision::decode(&unsupported),
			Err(RecoveryRecordError::UnsupportedEvidence)
		);
	}
	let mut nonminimal = canonical.clone();
	nonminimal.insert(nonminimal.len() - 1, 0x18);
	assert_eq!(
		RetainedPublicationDecision::decode(&nonminimal),
		Err(RecoveryRecordError::NonCanonical)
	);
	let mut zero = canonical;
	*zero.last_mut().expect("effect sequence") = 0;
	assert_eq!(
		RetainedPublicationDecision::decode(&zero),
		Err(RecoveryRecordError::InvalidEffectSequence)
	);
}

#[test]
fn retained_decision_checks_immediate_metadata_predecessor_sequence_and_digest() {
	let history = history(1, context(3), FILE);
	let record = history.decision(2);
	let payload = record.encode();
	let frame = path_frame(
		history.metadata.head(),
		FrameKind::RecoveryDecision,
		&payload,
	);
	assert_eq!(RetainedPublicationDecision::from_frame(&frame), Ok(record));
	let wrong_kind = path_frame(
		history.metadata.head(),
		FrameKind::RecoveryStarted,
		&payload,
	);
	assert_eq!(
		RetainedPublicationDecision::from_frame(&wrong_kind),
		Err(RecoveryRecordError::WrongRecordKind {
			expected: FrameKind::RecoveryDecision,
			actual: FrameKind::RecoveryStarted,
		})
	);
	for before in [
		history.verification.head(),
		reference(history.metadata.head().sequence(), 0x88),
	] {
		let forked = path_frame(before, FrameKind::RecoveryDecision, &payload);
		assert_eq!(
			RetainedPublicationDecision::from_frame(&forked),
			Err(RecoveryRecordError::InvalidFrameOrder)
		);
	}
}

#[test]
fn retained_decision_binds_fresh_evidence_owner_and_independent_identities() {
	let history = history(1, context(3), FILE);
	let decision = history.decision(2);
	let wrong_directory = RecoveryDirectories {
		stage: LinuxFileIdentity::new(5, 15),
		..DIRECTORIES
	};
	assert_eq!(
		decision.validate_evidence(history.frames(), OWNER, DIRECTORIES, SOURCE, 1),
		Ok(())
	);
	for (owner, directories, source) in [
		(OwnerDigest::from_bytes([0xaa; 32]), DIRECTORIES, SOURCE),
		(OWNER, wrong_directory, SOURCE),
		(OWNER, DIRECTORIES, FILE),
	] {
		assert_eq!(
			decision.validate_evidence(history.frames(), owner, directories, source, 1),
			Err(RecoveryRecordError::BindingMismatch)
		);
	}
}

#[test]
fn retained_decision_refuses_stale_verification_or_a_different_retained_stage() {
	for history in [
		history(1, context(2), FILE),
		history(1, context(3), LinuxFileIdentity::new(5, 23)),
	] {
		assert_eq!(
			history
				.decision(2)
				.validate_evidence(history.frames(), OWNER, DIRECTORIES, SOURCE, 1),
			Err(RecoveryRecordError::BindingMismatch)
		);
	}
}

#[test]
fn retained_decision_refuses_same_sequence_frames_from_a_forked_chain() {
	let history = history(1, context(3), FILE);
	let before_verification = reference(history.started.head().sequence(), 0x77);
	let verification = path_frame(
		before_verification,
		FrameKind::VerificationRecorded,
		history.verification.payload(),
	);
	let metadata = path_frame(
		verification.head(),
		FrameKind::MetadataRecorded,
		history.metadata.payload(),
	);
	let fork = History {
		verification,
		metadata,
		..history
	};
	assert_eq!(
		fork.decision(2)
			.validate_evidence(fork.frames(), OWNER, DIRECTORIES, SOURCE, 1),
		Err(RecoveryRecordError::InvalidFrameOrder)
	);
}

#[test]
fn unused_reservations_are_burned_and_effect_sequence_cannot_wrap() {
	let history = history(2, context(3), FILE);
	for (last, next, expected) in [
		(1, 2, Err(RecoveryRecordError::InvalidEffectSequence)),
		(2, 2, Err(RecoveryRecordError::InvalidEffectSequence)),
		(2, 3, Ok(())),
		(3, 4, Ok(())),
		(3, 5, Err(RecoveryRecordError::InvalidEffectSequence)),
		(u64::MAX - 1, u64::MAX, Ok(())),
		(u64::MAX, 1, Err(RecoveryRecordError::InvalidEffectSequence)),
	] {
		let decision = history.decision(next);
		assert_eq!(
			decision.validate_evidence(history.frames(), OWNER, DIRECTORIES, SOURCE, last),
			expected,
			"last reservation {last}, new sequence {next}"
		);
	}
}

#[test]
fn zero_cannot_be_the_effect_sequence_of_the_prior_intent() {
	let history = history(0, context(3), FILE);
	assert_eq!(
		history
			.decision(1)
			.validate_evidence(history.frames(), OWNER, DIRECTORIES, SOURCE, 0),
		Err(RecoveryRecordError::InvalidEffectSequence)
	);
}

#[test]
fn largest_retained_decision_fits_the_bounded_codec() {
	let record = RetainedPublicationDecision::new(
		context(u64::MAX),
		ENTRY,
		reference(u64::MAX - 3, 0x66),
		RetainedPublicationEvidence {
			stage: LinuxFileIdentity::new(u64::MAX, u64::MAX),
			directories: RecoveryDirectories {
				stage: LinuxFileIdentity::new(u64::MAX, u64::MAX - 1),
				destination: LinuxFileIdentity::new(u64::MAX, u64::MAX - 2),
			},
			verification: reference(u64::MAX - 2, 0x77),
			metadata: reference(u64::MAX - 1, 0x88),
		},
		u64::MAX,
	)
	.expect("maximum widths fit the local profile");
	assert_eq!(
		RetainedPublicationDecision::decode(&record.encode()),
		Ok(record)
	);
}

#[test]
fn retained_decision_rejects_reserved_references_bad_order_and_aliased_stage() {
	let history = history(1, context(3), FILE);
	let decision = history.decision(2);
	let evidence = decision.evidence();
	for (started, evidence, expected) in [
		(
			ChainHead::start(),
			evidence,
			RecoveryRecordError::InvalidReference,
		),
		(
			decision.started(),
			RetainedPublicationEvidence {
				metadata: reference(evidence.metadata.sequence() + 1, 0x88),
				..evidence
			},
			RecoveryRecordError::InvalidFrameOrder,
		),
		(
			decision.started(),
			RetainedPublicationEvidence {
				stage: STAGE_DIR,
				..evidence
			},
			RecoveryRecordError::InvalidIdentityScope,
		),
	] {
		assert_eq!(
			RetainedPublicationDecision::new(context(3), ENTRY, started, evidence, 2),
			Err(expected)
		);
	}
}

struct History {
	intent: Frame,
	started: Frame,
	verification: Frame,
	metadata: Frame,
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

	fn decision(&self, effect_sequence: u64) -> RetainedPublicationDecision {
		RetainedPublicationDecision::new(
			context(3),
			ENTRY,
			self.started.head(),
			RetainedPublicationEvidence {
				stage: FILE,
				directories: DIRECTORIES,
				verification: self.verification.head(),
				metadata: self.metadata.head(),
			},
			effect_sequence,
		)
		.expect("retained decision fixture")
	}
}

fn history(
	prior_effect: u64,
	verification_context: JournalContext,
	observed_stage: LinuxFileIdentity,
) -> History {
	let prior = context(2);
	let intent = PublishIntent {
		context: PublishIntentContext {
			job: prior.job,
			epoch: prior.epoch,
			entry: ENTRY,
			effect_sequence: prior_effect,
			plan_digest: prior.plan_digest,
		},
		target: PublishIntentTarget {
			stage: FILE,
			parent: TARGET_DIR,
			component: UnixComponent::new(b"target").expect("fixture filename"),
			verification_digest: VerificationDigest::from_bytes([0x35; 32]),
			primitive: PublicationPrimitive::LinuxRenameNoReplace,
		},
	};
	let intent = path_frame(
		ChainHead::start(),
		FrameKind::PublishIntent,
		&intent.encode(),
	);
	let started = RecoveryStarted::new(
		context(3),
		ENTRY,
		JournalEpoch::new(2),
		RecoveryStartEvidence {
			intent: intent.head(),
			preceding: intent.head(),
			authorization: OWNER,
		},
	)
	.expect("first recovery after the fixture intent");
	let started = path_frame(intent.head(), FrameKind::RecoveryStarted, &started.encode());
	let verification = VerificationRecorded::new(
		verification_context,
		ENTRY,
		StreamEvidence {
			identity: SOURCE,
			..stream()
		},
		StreamEvidence {
			identity: observed_stage,
			..stream()
		},
	)
	.expect("matching stream measurements");
	let verification = path_frame(
		started.head(),
		FrameKind::VerificationRecorded,
		&verification.encode(),
	);
	let timestamp = OwnerTimestamp::new(1, 2).expect("fixture timestamp");
	let metadata = MetadataRecorded {
		context: context(3),
		entry: ENTRY,
		stage: FILE,
		metadata: BasicMetadata::new(0o600, 1000, 1000, timestamp, timestamp)
			.expect("fixture metadata"),
	};
	let metadata = path_frame(
		verification.head(),
		FrameKind::MetadataRecorded,
		&metadata.encode(),
	);
	History {
		intent,
		started,
		verification,
		metadata,
	}
}
