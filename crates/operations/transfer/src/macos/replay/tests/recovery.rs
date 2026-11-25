use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	DarwinMetadataRecorded, DarwinNamespaceObservation, DarwinPhaseError, DarwinPublicationNames,
	DarwinPublicationOutcome, DarwinPublishedRecoveryEvidence, DarwinReceiptCommitted,
	DarwinReceiptDigest, DarwinRecoveryDecision, DarwinRecoveryDecisionFrames,
	DarwinRecoveryHistory, DarwinRecoveryStarted, DarwinVerificationRecorded,
};

use super::fixture::{Fixture, History};
use super::{DarwinJournalBoundary, DarwinJournalTail, DarwinReplayError, DarwinReplayStatus};

#[test]
fn accepts_one_recovery_generation_after_each_supported_original_attempt() {
	let fixture = Fixture::new();
	let cases = [
		(fixture.records.prefix(6), DarwinReplayStatus::Uncertain),
		(
			observed(&fixture, DarwinPublicationOutcome::UncertainRename),
			DarwinReplayStatus::Uncertain,
		),
		(
			observed(
				&fixture,
				DarwinPublicationOutcome::RenameConfirmedIncomplete,
			),
			DarwinReplayStatus::PublishedIncomplete,
		),
		(
			fixture.records.prefix(7),
			DarwinReplayStatus::PublishedIncomplete,
		),
		(
			fixture.records.prefix(8),
			DarwinReplayStatus::PublishedIncomplete,
		),
	];
	for (mut history, status) in cases {
		let original_count = history.frames.len();
		append_started(&fixture, &mut history);
		append_decision(&fixture, &mut history);
		for index in original_count..history.frames.len() {
			let preceding = &history.frames[index - 1];
			let frame = &history.frames[index];
			let start = history.ends[index - 1];
			let end = history.ends[index];
			let clean = fixture.replay(&history.bytes[..end]).unwrap();
			assert_eq!(clean.status(), status);
			assert_eq!(clean.tail(), DarwinJournalTail::Clean);
			assert_eq!(clean.frame(frame.kind()), Some(frame));
			assert_eq!(
				clean.boundary(),
				DarwinJournalBoundary {
					head: frame.head(),
					offset: end as u64,
				}
			);
			assert!(matches!(
				clean.validate_receipt(&fixture.plan, &[]),
				Err(DarwinReplayError::MissingReceiptCommitment)
			));

			for cut in (start + 1)..end {
				let torn = fixture.replay(&history.bytes[..cut]).unwrap();
				assert_eq!(torn.status(), status);
				assert_eq!(torn.frame(frame.kind()), None, "cut at byte {cut}");
				assert_eq!(
					torn.tail(),
					DarwinJournalTail::Torn {
						bytes_read: cut - start,
					}
				);
				assert_eq!(
					torn.boundary(),
					DarwinJournalBoundary {
						head: preceding.head(),
						offset: start as u64,
					}
				);
			}
		}
	}
}

#[test]
fn rejects_recovery_records_outside_the_single_supported_suffix() {
	let fixture = Fixture::new();
	let mut recovery = fixture.records.prefix(8);
	append_started(&fixture, &mut recovery);
	append_decision(&fixture, &mut recovery);
	let started = &recovery.frames[8];
	let decision = &recovery.frames[9];

	let mut skipped_start = fixture.records.prefix(8);
	skipped_start.append(decision.kind(), decision.payload());
	assert_unexpected(&fixture, &skipped_start, FrameKind::RecoveryDecision);

	let mut committed = fixture.records.prefix(8);
	let commitment = DarwinReceiptCommitted::new(
		committed.last(),
		DarwinReceiptDigest::from_bytes([0xAB; 32]),
	)
	.unwrap();
	committed.append(FrameKind::ReceiptCommitted, &commitment.encode());
	committed.append(started.kind(), started.payload());
	assert_unexpected(&fixture, &committed, FrameKind::RecoveryStarted);

	for (prefix, kind) in [
		(9, FrameKind::RecoveryStarted),
		(9, FrameKind::ReceiptCommitted),
		(10, FrameKind::RecoveryStarted),
		(10, FrameKind::RecoveryDecision),
		(10, FrameKind::ReceiptCommitted),
		(10, FrameKind::PublishIntent),
	] {
		let mut invalid = recovery.prefix(prefix);
		invalid.append(kind, &[]);
		assert_unexpected(&fixture, &invalid, kind);
	}
}

#[test]
fn requires_the_exact_original_attempt_and_recovery_start() {
	let fixture = Fixture::new();
	let mut published = fixture.records.prefix(7);
	append_started(&fixture, &mut published);
	append_decision(&fixture, &mut published);
	let published_start = &published.frames[7];
	let published_decision = published.last();

	let mut uncertain = observed(&fixture, DarwinPublicationOutcome::UncertainRename);
	uncertain.append(published_start.kind(), published_start.payload());
	assert!(matches!(
		fixture.replay(&uncertain.bytes),
		Err(DarwinReplayError::Phase(
			DarwinPhaseError::InvalidFrameOrder
		))
	));

	let mut uncertain = observed(&fixture, DarwinPublicationOutcome::UncertainRename);
	append_started(&fixture, &mut uncertain);
	uncertain.append(published_decision.kind(), published_decision.payload());
	assert!(matches!(
		fixture.replay(&uncertain.bytes),
		Err(DarwinReplayError::Phase(_))
	));
}

#[test]
fn rejects_a_recovery_start_even_with_an_exact_binding_to_an_ineligible_outcome() {
	let fixture = Fixture::new();
	let mut published = fixture.records.prefix(7);
	let previous_digest = published.last().head().digest();
	append_started(&fixture, &mut published);
	for outcome in [
		DarwinPublicationOutcome::Conflict,
		DarwinPublicationOutcome::RejectedBeforeRename,
	] {
		let mut original = observed(&fixture, outcome);
		let start = published.last();
		let mut payload = start.payload().to_vec();
		let offset = find_digest(&payload, &previous_digest);
		let next = offset + previous_digest.len();
		payload[offset..next].copy_from_slice(&original.last().head().digest());
		original.append(start.kind(), &payload);
		assert!(DarwinRecoveryStarted::from_frame(original.last()).is_ok());
		assert!(matches!(
			fixture.replay(&original.bytes),
			Err(DarwinReplayError::Phase(
				DarwinPhaseError::InconsistentObservation
			))
		));
	}
}

#[test]
fn rejects_a_complete_decision_with_different_stream_evidence() {
	let fixture = Fixture::new();
	let mut history = fixture.records.prefix(8);
	append_started(&fixture, &mut history);
	append_decision(&fixture, &mut history);
	let stream = DarwinVerificationRecorded::from_frame(&history.frames[3])
		.unwrap()
		.stage();
	let mut payload = history.last().payload().to_vec();
	let digest_offset = find_digest(&payload, stream.digest.as_bytes());
	payload[digest_offset] ^= 1;
	let mut different = history.prefix(9);
	different.append(FrameKind::RecoveryDecision, &payload);
	assert!(matches!(
		fixture.replay(&different.bytes),
		Err(DarwinReplayError::Phase(DarwinPhaseError::StreamMismatch))
	));
}

fn find_digest(payload: &[u8], digest: &[u8; 32]) -> usize {
	payload
		.windows(digest.len())
		.position(|bytes| bytes == digest)
		.unwrap()
}

fn assert_unexpected(fixture: &Fixture, history: &History, kind: FrameKind) {
	assert!(matches!(
		fixture.replay(&history.bytes),
		Err(DarwinReplayError::UnexpectedRecord { found, .. }) if found == kind
	));
}

fn observed(fixture: &Fixture, outcome: DarwinPublicationOutcome) -> History {
	let mut history = fixture.records.prefix(6);
	let payload = fixture.observation(history.last(), outcome);
	history.append(FrameKind::PublishObserved, &payload);
	history
}

fn append_started(fixture: &Fixture, history: &mut History) {
	let started = DarwinRecoveryStarted::new(evidence(fixture, history, history.last())).unwrap();
	history.append(FrameKind::RecoveryStarted, &started.encode());
}

fn append_decision(fixture: &Fixture, history: &mut History) {
	let started = history.last();
	let preceding = &history.frames[history.frames.len() - 2];
	let accepted = evidence(fixture, history, preceding);
	let stream = DarwinVerificationRecorded::from_frame(accepted.verification)
		.unwrap()
		.stage();
	let metadata = DarwinMetadataRecorded::from_frame(accepted.metadata)
		.unwrap()
		.metadata();
	let decision = DarwinRecoveryDecision::new(
		DarwinRecoveryDecisionFrames {
			started,
			history: accepted,
		},
		DarwinPublishedRecoveryEvidence {
			names: DarwinPublicationNames {
				target: DarwinNamespaceObservation::Present(fixture.stage.identity),
				stage: DarwinNamespaceObservation::Absent,
			},
			stage_directory: fixture.stage.directory,
			destination_directory: fixture.plan.destination().root_identity,
			stream,
			metadata,
		},
	)
	.unwrap();
	history.append(FrameKind::RecoveryDecision, &decision.encode());
}

fn evidence<'a>(
	fixture: &'a Fixture,
	history: &'a History,
	preceding: &'a Frame,
) -> DarwinRecoveryHistory<'a> {
	let frames = &history.frames;
	DarwinRecoveryHistory {
		owner: &fixture.owner,
		job: &frames[0],
		entry: &frames[1],
		seal: &frames[2],
		verification: &frames[3],
		metadata: &frames[4],
		intent: &frames[5],
		observed_before_durability: (preceding.kind() == FrameKind::DurabilityRecorded)
			.then(|| &frames[6]),
		preceding,
	}
}
