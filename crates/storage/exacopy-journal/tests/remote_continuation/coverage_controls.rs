use exacopy_journal::remote_download::replay::{RemoteReplayIssue, RemoteReplayMismatch};
use exacopy_journal::remote_download::{RemoteDownloadBody, RemoteUncertainBoundary};

use super::*;

#[test]
fn supplied_prefix_must_end_at_clean_complete_coverage_to_export_predecessor() {
	let run = Transcript::read(true);
	assert!(
		run.replay(&run.fixture.journal[..run.fixture.prefix_end])
			.complete_coverage_predecessor()
			.is_err()
	);
	for index in [0, 1] {
		let replay = run.replay(&run.prefix(index));
		assert_eq!(replay.history().boundary(), run.frames[index].1);
		assert!(replay.complete_coverage_predecessor().is_err());
	}

	let prefix = run.prefix(2);
	let replay = run.replay(&prefix);
	let accepted = replay.complete_coverage_predecessor().unwrap();
	assert_eq!(accepted.boundary(), run.frames[2].1);
	assert!(
		run.replay(&prefix[..prefix.len() - 1])
			.complete_coverage_predecessor()
			.is_err()
	);
	let mut trailing_witness = FrameWriter::new(prefix.clone(), accepted.boundary().head);
	trailing_witness
		.append(FrameKind::RemoteWitnessIntent, &vector("tail-witness"))
		.unwrap();
	let replay = run.replay(&trailing_witness.into_inner());
	assert_eq!(replay.history().boundary(), accepted.boundary());
	assert!(replay.complete_coverage_predecessor().is_err());
	assert!(matches!(
		replay.history().state(),
		exacopy_journal::remote_download::continuation::replay::RemoteContinuationState::ReconciliationRequired(
			RemoteReplayIssue::Record {
				kind: FrameKind::RemoteWitnessIntent,
				problem: RemoteReplayMismatch::UnsupportedKind,
				..
			}
		)
	));

	let active = run.fixture.expectation().claims;
	let failure = RemoteDownloadRecord::new(
		active.context,
		Some(accepted.boundary().head),
		RemoteDownloadBody::FailureRecorded {
			attempt: run.frames[0].1.head,
			epochs: active.epochs,
			boundary: RemoteUncertainBoundary::TerminalSource,
		},
	)
	.unwrap()
	.encode()
	.unwrap();
	let mut failed = FrameWriter::new(prefix, accepted.boundary().head);
	failed.append(FrameKind::FailureRecorded, &failure).unwrap();
	let replay = run.replay(&failed.into_inner());
	assert!(replay.history().recorded_uncertainty().is_some());
	assert!(replay.complete_coverage_predecessor().is_err());
}

#[test]
fn witness_from_another_real_complete_prefix_refuses() {
	let zero = Transcript::read(false);
	let tail = Transcript::read(true);
	let tail_replay = tail.full_replay();
	let tail_expected = tail.intent(&tail_replay);
	let (foreign, boundary) = &zero.frames[1];
	assert_eq!(
		tail.fixture
			.trust()
			.from_witness_intent_frame(foreign, *boundary, &tail_expected),
		Err(Error::FrameBinding),
	);
	let (foreign, boundary) = append(
		tail_expected.coverage.boundary(),
		FrameKind::RemoteWitnessIntent,
		foreign.payload(),
	);
	assert_eq!(
		tail.fixture
			.trust()
			.from_witness_intent_frame(&foreign, boundary, &tail_expected),
		Err(Error::Binding),
	);
}

#[test]
fn terminal_checkpoint_digest_is_bound_even_at_same_sequence_and_extent() {
	use exacopy_journal::remote_download::continuation::checkpoint::RemoteContinuedCheckpoint;

	let run = Transcript::read(true);
	let original = run.full_replay();
	let original = original.complete_coverage_predecessor().unwrap().boundary();

	let checkpoint = RemoteContinuedCheckpoint::from_frame(&run.frames[2].0).unwrap();
	let mut range = checkpoint.range();
	range.digest = StreamDigest::from_bytes([0xc7; 32]);
	let different = RemoteContinuedCheckpoint::new(
		checkpoint.context(),
		checkpoint.predecessor(),
		checkpoint.continuation(),
		checkpoint.epochs(),
		range,
	)
	.unwrap()
	.encode()
	.unwrap();
	let mut journal = FrameWriter::new(run.prefix(1), run.frames[1].1.head);
	journal
		.append(FrameKind::RangeCheckpoint, &different)
		.unwrap();
	let replay = run.replay(&journal.into_inner());
	let expected = run.intent(&replay);
	let alternate = expected.coverage.boundary();
	assert_eq!(alternate.head.sequence(), original.head.sequence());
	assert_eq!(alternate.offset, original.offset);
	assert_ne!(alternate.head.digest(), original.head.digest());

	let (foreign, boundary) = append(
		alternate,
		FrameKind::RemoteWitnessIntent,
		&vector("tail-witness"),
	);
	assert_eq!(
		run.fixture
			.trust()
			.from_witness_intent_frame(&foreign, boundary, &expected),
		Err(Error::Binding),
	);
}
