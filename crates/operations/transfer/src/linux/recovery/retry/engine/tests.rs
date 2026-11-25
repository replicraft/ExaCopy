use exacopy_journal::frame::FrameReader;

use super::*;

mod fixture;

use fixture::Fixture;

const CONTENT: &[u8] = b"retained";
const STAGE: LinuxFileIdentity = LinuxFileIdentity::new(1, 5);
const STAGE_DIRECTORY: LinuxFileIdentity = LinuxFileIdentity::new(1, 6);
const PRIOR_EPOCH: JournalEpoch = JournalEpoch::new(7);
const PRIOR_EFFECT: u64 = 11;
const MODE: u32 = 0o640;
const ACCESS_SECONDS: i64 = 23;
const ACCESS_NANOS: u32 = 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
	Flush,
	Measure,
	ReadBack,
	SourceCheck,
	NamespaceCheck,
	JournalOpen,
	Sync(FrameKind),
	Publish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailurePoint {
	StageIdentity,
	StageDirectory,
	IntentBarrier,
	SourceChanged,
	UncertainPublication,
	StageReadBack,
	AccessTime,
	SourceBytes,
}

#[test]
fn retry_gates_publication_on_fresh_evidence_and_records_exact_references() {
	use Action::*;

	let fixture = Fixture::new();
	let (result, trace, suffix) = fixture.run(None);
	result.unwrap();
	assert_eq!(
		trace,
		[
			Flush,
			Measure,
			ReadBack,
			SourceCheck,
			NamespaceCheck,
			JournalOpen,
			Sync(FrameKind::RecoveryStarted),
			Sync(FrameKind::VerificationRecorded),
			Sync(FrameKind::MetadataRecorded),
			Sync(FrameKind::RecoveryDecision),
			Sync(FrameKind::PublishIntent),
			SourceCheck,
			Publish,
			Sync(FrameKind::PublishObserved),
		],
	);

	let mut reader = FrameReader::new(suffix.as_slice(), fixture.journal.boundary.head);
	let start = reader.next_frame().unwrap().unwrap();
	let verification = reader.next_frame().unwrap().unwrap();
	let metadata = reader.next_frame().unwrap().unwrap();
	let decision = reader.next_frame().unwrap().unwrap();
	let intent = reader.next_frame().unwrap().unwrap();
	let observed = reader.next_frame().unwrap().unwrap();
	assert!(reader.next_frame().unwrap().is_none());

	let recovery = RecoveryStarted::from_frame(&start).unwrap();
	assert_eq!(recovery.prior_epoch(), PRIOR_EPOCH);
	assert_eq!(recovery.context().epoch.get(), PRIOR_EPOCH.get() + 1);
	assert_eq!(
		recovery.evidence().intent,
		fixture.journal.intent_head.unwrap()
	);
	assert_eq!(recovery.evidence().authorization, fixture.owner);
	let fresh = VerificationRecorded::from_frame(&verification).unwrap();
	assert_eq!(
		fresh.source(),
		fixture.journal.verification.unwrap().source()
	);
	assert_eq!(fresh.stage(), fixture.journal.verification.unwrap().stage());
	let retained = RetainedPublicationDecision::from_frame(&decision).unwrap();
	assert_eq!(retained.evidence().stage, STAGE);
	assert_eq!(retained.evidence().directories.stage, STAGE_DIRECTORY);
	assert_eq!(retained.evidence().verification, verification.head());
	assert_eq!(retained.evidence().metadata, metadata.head());
	assert_eq!(retained.started(), start.head());
	assert_eq!(retained.effect_sequence(), PRIOR_EFFECT + 1);
	let publication = PublishIntent::from_frame(&intent).unwrap();
	assert_eq!(publication.context.epoch, recovery.context().epoch);
	assert_eq!(publication.context.effect_sequence, PRIOR_EFFECT + 1);
	assert_eq!(publication.target.stage, STAGE);
	assert_eq!(
		publication.target.component,
		fixture.plan.destination().component
	);
	assert_eq!(
		publication.target.verification_digest,
		fresh.record_digest()
	);
	let observation = PublishObserved::from_frame(&observed).unwrap();
	assert_eq!(observation.intent(), intent.head());
	assert_eq!(
		observation.outcome(),
		PublicationOutcome::Published { target: STAGE }
	);
}

#[test]
fn retry_stops_at_each_failed_gate() {
	use Action::*;
	use FailurePoint::*;

	let fixture = Fixture::new();
	for (failure, last) in [
		(SourceBytes, Measure),
		(StageReadBack, ReadBack),
		(AccessTime, ReadBack),
		(IntentBarrier, Sync(FrameKind::PublishIntent)),
		(SourceChanged, SourceCheck),
		(UncertainPublication, Publish),
	] {
		let (result, trace, suffix) = fixture.run(Some(failure));
		assert!(result.is_err(), "{failure:?}");
		assert_eq!(trace.last(), Some(&last), "{failure:?}");
		assert_eq!(trace.contains(&Publish), failure == UncertainPublication);
		assert!(!trace.contains(&Sync(FrameKind::PublishObserved)));
		match failure {
			StageIdentity | StageDirectory => {
				unreachable!("the test covers only active retry gates")
			}
			SourceBytes => assert!(matches!(result, Err(RetryError::SourceMismatch))),
			StageReadBack => {
				assert!(matches!(
					result,
					Err(RetryError::Stage(RecoveryIssue::StreamMismatch))
				));
			}
			AccessTime => {
				assert!(matches!(
					result,
					Err(RetryError::Stage(RecoveryIssue::MetadataMismatch))
				));
			}
			IntentBarrier => {
				assert!(matches!(
					result,
					Err(RetryError::Append {
						kind: FrameKind::PublishIntent,
						..
					})
				));
			}
			SourceChanged => {
				assert!(matches!(
					result,
					Err(RetryError::SourcePolicy(StageFailure::Source(
						SourceChanged
					)))
				));
			}
			UncertainPublication => {
				assert!(matches!(
					result,
					Err(RetryError::Publish(UncertainPublication))
				));
			}
		}
		if matches!(failure, SourceBytes | StageReadBack | AccessTime) {
			assert!(suffix.is_empty(), "{failure:?} opened the journal");
		}
	}
}

#[test]
fn mismatched_stage_or_directory_never_grants_publication_authority() {
	let fixture = Fixture::new();
	for (failure, issue) in [
		(
			FailurePoint::StageIdentity,
			RecoveryIssue::UnrecognizedStage,
		),
		(
			FailurePoint::StageDirectory,
			RecoveryIssue::StageDirectoryBinding,
		),
	] {
		let (result, trace, suffix) = fixture.run(Some(failure));
		assert!(matches!(result, Err(RetryError::Stage(observed)) if observed == issue));
		assert!(trace.is_empty());
		assert!(suffix.is_empty());
	}
}

#[test]
fn exhausted_generation_or_effect_never_grants_publication_authority() {
	let mut fixture = Fixture::new();
	fixture.journal.latest_epoch = JournalEpoch::new(u64::MAX);
	let (result, trace, suffix) = fixture.run(None);
	assert!(matches!(result, Err(RetryError::EpochExhausted)));
	assert!(trace.is_empty());
	assert!(suffix.is_empty());

	fixture.journal.latest_epoch = PRIOR_EPOCH;
	fixture.journal.last_effect_sequence = u64::MAX;
	let (result, trace, suffix) = fixture.run(None);
	assert!(matches!(result, Err(RetryError::EffectSequenceExhausted)));
	assert!(trace.is_empty());
	assert!(suffix.is_empty());
}
