use std::num::NonZeroU64;

use exacopy_journal::frame::{ChainHead, Frame, FrameKind};
use exacopy_journal::{
	DarwinDurabilityRecorded, DarwinNamespaceObservation as Name, DarwinPhaseError,
	DarwinPublicationBarriers, DarwinPublicationNames, DarwinPublicationOutcome as Outcome,
	DarwinPublishIntent, DarwinPublishObserved, DarwinPublishedRecoveryEvidence,
	DarwinRecoveryDecision, DarwinRecoveryDecisionFrames, DarwinRecoveryHistory,
	DarwinRecoveryStarted, JournalEpoch, OwnerTimestamp, RecoveryDecision, RecoveryStarted,
	StreamDigest, StreamLength,
};

use super::fixture::{Fixture, PUBLIC_NAME, frame, native};
use minicbor::Decoder;

const ORIGINAL_EPOCH: u64 = 4;

struct History {
	fixture: Fixture<'static>,
	seal: Frame,
	verification: Frame,
	metadata: Frame,
	intent: Frame,
}

impl History {
	fn new(epoch: u64) -> Self {
		Self::with_effect(epoch, NonZeroU64::MIN)
	}

	fn with_effect(epoch: u64, effect: NonZeroU64) -> Self {
		let fixture = Fixture::with_epoch(39, PUBLIC_NAME, epoch);
		let seal = fixture.seal();
		let seal_frame = frame(FrameKind::StageSealed, &seal.encode(), fixture.frame.head());
		let verification = fixture.verify(&seal);
		let verification_frame = frame(
			FrameKind::VerificationRecorded,
			&verification.encode(),
			seal_frame.head(),
		);
		let metadata = fixture.metadata(&seal, &verification);
		let metadata_frame = frame(
			FrameKind::MetadataRecorded,
			&metadata.encode(),
			verification_frame.head(),
		);
		let intent = frame(
			FrameKind::PublishIntent,
			&DarwinPublishIntent::new(effect, &fixture.frame, &seal, &verification, &metadata)
				.unwrap()
				.encode(),
			metadata_frame.head(),
		);
		Self {
			fixture,
			seal: seal_frame,
			verification: verification_frame,
			metadata: metadata_frame,
			intent,
		}
	}

	fn start_history<'a>(&'a self, preceding: &'a Frame) -> DarwinRecoveryHistory<'a> {
		DarwinRecoveryHistory {
			owner: &self.fixture.owner,
			job: &self.fixture.job,
			entry: &self.fixture.frame,
			seal: &self.seal,
			verification: &self.verification,
			metadata: &self.metadata,
			intent: &self.intent,
			observed_before_durability: None,
			preceding,
		}
	}

	fn start(&self, preceding: &Frame) -> Frame {
		let started = DarwinRecoveryStarted::new(self.start_history(preceding)).unwrap();
		frame(
			FrameKind::RecoveryStarted,
			&started.encode(),
			preceding.head(),
		)
	}

	fn decision_frames<'a>(&'a self, started: &'a Frame) -> DarwinRecoveryDecisionFrames<'a> {
		DarwinRecoveryDecisionFrames {
			started,
			history: self.start_history(&self.intent),
		}
	}

	fn fresh(&self) -> DarwinPublishedRecoveryEvidence {
		DarwinPublishedRecoveryEvidence {
			names: DarwinPublicationNames {
				target: Name::Present(self.fixture.stage.identity),
				stage: Name::Absent,
			},
			stage_directory: self.fixture.stage.directory,
			destination_directory: self.fixture.parent,
			stream: self.fixture.measurements().1,
			metadata: self.fixture.required,
		}
	}

	fn observation(&self, outcome: Outcome) -> Frame {
		let observed =
			DarwinPublishObserved::new(&self.intent, outcome, self.fresh().names).unwrap();
		frame(
			FrameKind::PublishObserved,
			&observed.encode(),
			self.intent.head(),
		)
	}
}

#[test]
fn round_trips_independent_recovery_payloads_and_binds_the_original_effect() {
	let history = History::new(ORIGINAL_EPOCH);
	let started_frame = history.start(&history.intent);
	let started = DarwinRecoveryStarted::from_frame(&started_frame).unwrap();
	started
		.validate_evidence(history.start_history(&history.intent))
		.unwrap();
	assert_eq!(started.prior_epoch(), JournalEpoch::new(ORIGINAL_EPOCH));
	assert_eq!(
		started.binding().context.epoch,
		JournalEpoch::new(ORIGINAL_EPOCH + 1)
	);
	assert_eq!(started.intent(), history.intent.head());
	assert_eq!(started.preceding(), history.intent.head());

	let frames = history.decision_frames(&started_frame);
	let decision = DarwinRecoveryDecision::new(frames, history.fresh()).unwrap();
	let decision_frame = frame(
		FrameKind::RecoveryDecision,
		&decision.encode(),
		started_frame.head(),
	);
	let decoded = DarwinRecoveryDecision::from_frame(&decision_frame).unwrap();
	decoded.validate_evidence(frames).unwrap();
	assert_eq!(decoded, decision);
	assert_eq!(decision.evidence(), history.fresh());
	assert_eq!(decision.binding(), started.binding());
	assert_eq!(decision.started(), started_frame.head());
	assert_eq!(decision.verification(), history.verification.head());
	assert_eq!(decision.metadata(), history.metadata.head());

	assert_golden(&started.encode(), include_str!("recovery-started.hex"));
	assert_golden(&decision.encode(), include_str!("recovery-decision.hex"));
}

#[test]
fn starts_only_at_an_eligible_original_boundary() {
	let history = History::new(ORIGINAL_EPOCH);
	for outcome in [
		Outcome::UncertainRename,
		Outcome::RenameConfirmedIncomplete,
		Outcome::Published,
	] {
		let observed = history.observation(outcome);
		let started = history.start(&observed);
		assert_eq!(
			DarwinRecoveryStarted::from_frame(&started)
				.unwrap()
				.preceding(),
			observed.head()
		);
	}
	for outcome in [
		Outcome::Conflict,
		Outcome::RejectedBeforeRename,
		Outcome::ReconciledPublished,
	] {
		let observed = history.observation(outcome);
		assert_eq!(
			DarwinRecoveryStarted::new(history.start_history(&observed)),
			Err(DarwinPhaseError::InconsistentObservation),
		);
	}
	let observed = history.observation(Outcome::Published);
	let fresh = history.fresh();
	let durability = DarwinDurabilityRecorded::new(
		&history.metadata,
		&history.intent,
		&observed,
		DarwinPublicationBarriers {
			stage_directory: fresh.stage_directory,
			destination_directory: fresh.destination_directory,
		},
	)
	.unwrap();
	let durable = frame(
		FrameKind::DurabilityRecorded,
		&durability.encode(),
		observed.head(),
	);
	assert_eq!(
		DarwinRecoveryStarted::new(history.start_history(&durable)),
		Err(DarwinPhaseError::InvalidFrameOrder),
	);
	let durable_history = DarwinRecoveryHistory {
		observed_before_durability: Some(&observed),
		..history.start_history(&durable)
	};
	DarwinRecoveryStarted::new(durable_history).unwrap();
	let fork = history.observation(Outcome::RenameConfirmedIncomplete);
	assert_eq!(
		DarwinRecoveryStarted::new(DarwinRecoveryHistory {
			observed_before_durability: Some(&fork),
			..durable_history
		}),
		Err(DarwinPhaseError::InvalidFrameOrder),
	);
	let started = history.start(&history.intent);
	assert_eq!(
		DarwinRecoveryStarted::new(history.start_history(&started)),
		Err(DarwinPhaseError::InvalidFrameOrder),
	);
	let other_effect = History::with_effect(ORIGINAL_EPOCH, NonZeroU64::MAX);
	assert_eq!(
		DarwinRecoveryStarted::new(other_effect.start_history(&other_effect.intent)),
		Err(DarwinPhaseError::BindingMismatch),
	);
	let exhausted = History::new(u64::MAX);
	assert_eq!(
		DarwinRecoveryStarted::new(exhausted.start_history(&exhausted.intent)),
		Err(DarwinPhaseError::InvalidRecoveryEpoch),
	);
}

#[test]
fn rejects_forked_references_and_unrelated_authenticated_owner_or_entry() {
	let history = History::new(ORIGINAL_EPOCH);
	let other = History::new(ORIGINAL_EPOCH - 1);
	let accepted = history.start_history(&history.intent);
	assert!(
		DarwinRecoveryStarted::new(DarwinRecoveryHistory {
			entry: &other.fixture.frame,
			..accepted
		})
		.is_err()
	);
	let alternate_owner = exacopy_journal::DarwinOwnerRecord::sign(
		history.fixture.owner.manifest().clone(),
		&ed25519_dalek::SigningKey::from_bytes(&[0xab; 32]),
	)
	.unwrap();
	assert!(
		DarwinRecoveryStarted::new(DarwinRecoveryHistory {
			owner: &alternate_owner,
			..accepted
		})
		.is_err()
	);

	let started_frame = history.start(&history.intent);
	let frames = history.decision_frames(&started_frame);
	let decision = DarwinRecoveryDecision::new(frames, history.fresh()).unwrap();
	for fork in [
		DarwinRecoveryHistory {
			intent: &other.intent,
			..accepted
		},
		DarwinRecoveryHistory {
			verification: &other.verification,
			..accepted
		},
		DarwinRecoveryHistory {
			metadata: &other.metadata,
			..accepted
		},
	] {
		assert!(
			DarwinRecoveryStarted::new(fork).is_err(),
			"accepted fork {fork:?}"
		);
		assert!(
			decision
				.validate_evidence(DarwinRecoveryDecisionFrames {
					history: fork,
					..frames
				})
				.is_err(),
			"accepted fork {fork:?}"
		);
	}
	let observed = history.observation(Outcome::UncertainRename);
	assert_eq!(
		decision.validate_evidence(DarwinRecoveryDecisionFrames {
			history: history.start_history(&observed),
			..frames
		}),
		Err(DarwinPhaseError::BindingMismatch),
	);
	let wrong_predecessor = |record: FrameKind, payload: &[u8], expected: ChainHead| {
		frame(
			record,
			payload,
			ChainHead::after(expected.sequence(), [0x77; 32]).unwrap(),
		)
	};
	assert_eq!(
		DarwinRecoveryStarted::from_frame(&wrong_predecessor(
			FrameKind::RecoveryStarted,
			started_frame.payload(),
			history.intent.head(),
		)),
		Err(DarwinPhaseError::InvalidFrameOrder),
	);
	assert_eq!(
		DarwinRecoveryDecision::from_frame(&wrong_predecessor(
			FrameKind::RecoveryDecision,
			&decision.encode(),
			started_frame.head(),
		)),
		Err(DarwinPhaseError::InvalidFrameOrder),
	);
}

#[test]
fn rejects_ambiguous_names_changed_data_and_changed_metadata() {
	let history = History::new(ORIGINAL_EPOCH);
	let started = history.start(&history.intent);
	let frames = history.decision_frames(&started);
	let fresh = history.fresh();
	for names in [
		DarwinPublicationNames {
			stage: Name::Unobserved,
			..fresh.names
		},
		DarwinPublicationNames {
			stage: Name::Present(native(3)),
			..fresh.names
		},
		DarwinPublicationNames {
			target: Name::Absent,
			..fresh.names
		},
		DarwinPublicationNames {
			target: Name::PresentUnidentified,
			..fresh.names
		},
		DarwinPublicationNames {
			target: Name::Present(native(3)),
			..fresh.names
		},
	] {
		assert_eq!(
			DarwinRecoveryDecision::new(frames, DarwinPublishedRecoveryEvidence { names, ..fresh }),
			Err(DarwinPhaseError::InconsistentObservation),
		);
	}
	for stream in [
		exacopy_journal::DarwinStreamEvidence {
			length: StreamLength::new(40).unwrap(),
			..fresh.stream
		},
		exacopy_journal::DarwinStreamEvidence {
			digest: StreamDigest::from_bytes([0x77; 32]),
			..fresh.stream
		},
	] {
		assert_eq!(
			DarwinRecoveryDecision::new(
				frames,
				DarwinPublishedRecoveryEvidence { stream, ..fresh }
			),
			Err(DarwinPhaseError::StreamMismatch),
		);
	}
	let mut metadata = fresh.metadata;
	metadata.accessed_at = OwnerTimestamp::new(555, 0).unwrap();
	assert_eq!(
		DarwinRecoveryDecision::new(
			frames,
			DarwinPublishedRecoveryEvidence { metadata, ..fresh }
		),
		Err(DarwinPhaseError::MetadataMismatch),
	);
	assert_eq!(
		DarwinRecoveryDecision::new(
			frames,
			DarwinPublishedRecoveryEvidence {
				stage_directory: native(16),
				..fresh
			}
		),
		Err(DarwinPhaseError::IdentityMismatch),
	);
	assert_eq!(
		DarwinRecoveryDecision::new(
			frames,
			DarwinPublishedRecoveryEvidence {
				destination_directory: fresh.stage_directory,
				..fresh
			}
		),
		Err(DarwinPhaseError::AliasedIdentity),
	);
}

#[test]
fn canonical_forms_refuse_truncation_overflow_extra_bytes_and_linux_decoders() {
	let history = History::new(ORIGINAL_EPOCH);
	let started = history.start(&history.intent);
	let decision = DarwinRecoveryDecision::new(history.decision_frames(&started), history.fresh())
		.unwrap()
		.encode();
	// The start body may make a canonical claim that still cannot join an older epoch.
	let mut stale_start = started.payload().to_vec();
	let mut decoder = Decoder::new(&stale_start);
	decoder.map().unwrap();
	for _ in 0..2 {
		decoder.skip().unwrap(); // Header key.
		decoder.skip().unwrap(); // Header value.
	}
	assert_eq!(decoder.u8().unwrap(), 2);
	let epoch = decoder.position();
	stale_start[epoch] = u8::try_from(ORIGINAL_EPOCH).unwrap();
	assert_eq!(
		DarwinRecoveryStarted::decode(&stale_start),
		Err(DarwinPhaseError::InvalidRecoveryEpoch),
	);
	assert!(RecoveryStarted::decode(started.payload()).is_err());
	assert!(RecoveryDecision::decode(&decision).is_err());
	check_wire(started.payload(), DarwinRecoveryStarted::decode);
	check_wire(&decision, DarwinRecoveryDecision::decode);
	let mut inconsistent = decision;
	*inconsistent.last_mut().unwrap() = 0;
	assert_eq!(
		DarwinRecoveryDecision::decode(&inconsistent),
		Err(DarwinPhaseError::InvalidCbor)
	);
}

fn assert_golden(payload: &[u8], golden: &str) {
	let (golden, remainder) = golden.trim().as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty());
	assert_eq!(golden.len(), payload.len());
	for (hex, &byte) in golden.iter().zip(payload) {
		let hex = core::str::from_utf8(hex).unwrap();
		assert_eq!(u8::from_str_radix(hex, 16).unwrap(), byte);
	}
}

fn check_wire<T: core::fmt::Debug>(
	payload: &[u8],
	decode: impl Fn(&[u8]) -> Result<T, DarwinPhaseError>,
) {
	for end in 0..payload.len() {
		assert!(
			decode(&payload[..end]).is_err(),
			"accepted truncation at byte {end}"
		);
	}
	let mut trailing = payload.to_vec();
	trailing.push(0);
	assert_eq!(
		decode(&trailing).unwrap_err(),
		DarwinPhaseError::TrailingBytes
	);
	let mut noncanonical = payload.to_vec();
	noncanonical.splice(1..2, [0x18, 0]);
	assert_eq!(
		decode(&noncanonical).unwrap_err(),
		DarwinPhaseError::NonCanonical
	);
	assert_eq!(
		decode(&[0; 1024]).unwrap_err(),
		DarwinPhaseError::PayloadTooLong
	);
}
