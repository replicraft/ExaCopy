use exacopy_journal::remote_download::continuation::CoverageBasis;
use exacopy_journal::remote_download::witness::RemoteWitnessIntentExpectation;

use super::super::{append, vector};
use super::{FRESH, Phase, Transcript, assert_clean, recorded, scan};
use crate::{ChainHead, FrameKind, FrameReader, RemoteReplayBoundary};

fn mixed_complete_coverage_signs_existing_kind41_at_exact_terminal_rows() {
	for tail in [false, true] {
		let run = Transcript::read(tail);
		let terminal = if tail { 2 } else { 0 };
		let bytes = run.prefix(terminal);
		let replay = scan(&run, bytes.as_slice(), FRESH);
		assert_clean(&replay, &bytes, Phase::ContinuedCapture);
		let coverage = replay.complete_coverage_predecessor().unwrap();
		let boundary = run.frames[terminal].1;
		assert_eq!(coverage.boundary(), boundary);
		let history = replay.active_prefix_history().unwrap();
		assert_eq!(history.covered_extent(), history.source().length().get());
		let ranges: Vec<_> = history
			.ranges()
			.map(|range| (range.offset, range.length))
			.collect();
		if tail {
			assert_eq!(ranges, [(0, 4), (4, 1), (5, 1)]);
			assert_eq!(
				history.coverage_basis(),
				CoverageBasis::Checkpoint {
					head: boundary.head,
					ordinal: 2,
				}
			);
		} else {
			assert_eq!(ranges, [(0, 4)]);
			assert_eq!(
				history.coverage_basis(),
				CoverageBasis::ContinuedPrefix(boundary.head)
			);
		}

		let continuation = run.full_replay();
		let expected = RemoteWitnessIntentExpectation {
			coverage,
			..run.intent(&continuation)
		};
		let trust = run.fixture.trust();
		let payload = trust
			.sign_witness_intent(&expected, &run.fixture.key)
			.unwrap();
		if tail {
			assert_eq!(payload, vector("tail-witness"));
		} else {
			assert_eq!(payload, run.frames[1].0.payload());
		}
		let (frame, end) = append(boundary, FrameKind::RemoteWitnessIntent, &payload);
		let witness = trust
			.from_witness_intent_frame(&frame, end, &expected)
			.unwrap();
		assert_eq!(
			witness.witness_name(),
			*b"witness.61616161616161616161616161616161"
		);
	}
}

fn mixed_coverage_selects_only_the_active_repeated_continuation() {
	let run = Transcript::read(false);
	let bytes = recorded("repeated-v2");
	let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());
	let mut continued = Vec::new();
	while let Some(frame) = reader.next_frame().unwrap() {
		if frame.kind() == FrameKind::RemoteCaptureContinued {
			continued.push(RemoteReplayBoundary {
				head: frame.head(),
				offset: reader.offset(),
			});
		}
	}
	let [old, current] = continued.as_slice() else {
		panic!("the repeat vector must include both accepted declarations");
	};
	let incomplete = &bytes[..usize::try_from(old.offset).unwrap()];
	let prior = scan(&run, incomplete, FRESH);
	assert_clean(&prior, incomplete, Phase::ContinuedCapture);
	assert!(prior.complete_coverage_predecessor().is_err());

	let prefix = &bytes[..usize::try_from(current.offset).unwrap()];
	let active = scan(&run, prefix, FRESH);
	assert_clean(&active, prefix, Phase::ContinuedCapture);
	assert_eq!(active.pass_count(), 3);
	assert_eq!(
		active.complete_coverage_predecessor().unwrap().boundary(),
		*current
	);
	let history = active.active_prefix_history().unwrap();
	assert_eq!(history.epochs().run.get(), 3);
	assert_eq!(
		history.coverage_basis(),
		CoverageBasis::ContinuedPrefix(current.head)
	);
	assert_eq!(
		history
			.ranges()
			.map(|range| (range.offset, range.length))
			.collect::<Vec<_>>(),
		[(0, 6)]
	);
}

fn mixed_coverage_refuses_incomplete_and_unclean_cuts_and_other_phases() {
	let tail = Transcript::read(true);
	for index in [0, 1] {
		let bytes = tail.prefix(index);
		let replay = scan(&tail, bytes.as_slice(), FRESH);
		assert_clean(&replay, &bytes, Phase::ContinuedCapture);
		assert!(replay.complete_coverage_predecessor().is_err());
	}

	let run = Transcript::read(false);
	let original = &run.fixture.journal[..run.fixture.prefix_end];
	let legacy = scan(&run, original, FRESH);
	assert!(legacy.complete_coverage_predecessor().is_err());
	let complete = run.prefix(0);
	let with_witness = run.prefix(1);
	let torn = scan(&run, &with_witness[..complete.len() + 1], FRESH);
	assert_eq!(torn.phase(), Phase::ContinuedCapture);
	assert_eq!(torn.boundary(), run.frames[0].1);
	assert!(torn.issue().is_some());
	assert!(torn.complete_coverage_predecessor().is_err());
	let after_intent = scan(&run, with_witness.as_slice(), FRESH);
	assert_clean(
		&after_intent,
		&with_witness,
		Phase::WitnessIntentRequiresInspection,
	);
	assert!(after_intent.complete_coverage_predecessor().is_err());

	for (label, phase) in [
		("pre-intent-failure", Phase::Uncertain),
		("conflict", Phase::Conflict),
		("retire-preserved", Phase::Retired),
		("published", Phase::ReceiptCommitted),
	] {
		let bytes = recorded(label);
		let replay = scan(&run, bytes.as_slice(), FRESH);
		assert_eq!(replay.phase(), phase, "{label}");
		assert!(replay.complete_coverage_predecessor().is_err(), "{label}");
	}
}

#[test]
fn mixed_coverage_predecessor_requires_exact_complete_active_history() {
	mixed_complete_coverage_signs_existing_kind41_at_exact_terminal_rows();
	mixed_coverage_selects_only_the_active_repeated_continuation();
	mixed_coverage_refuses_incomplete_and_unclean_cuts_and_other_phases();
}
