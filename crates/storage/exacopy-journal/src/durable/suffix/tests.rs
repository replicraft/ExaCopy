use std::io;

use super::super::{DurableJournalError, SyncedFrame};
use crate::frame::{ChainHead, FRAME_OVERHEAD_BYTES, FrameKind, FrameReadError, FrameReader};

mod fixture;

use fixture::{State, chain, chain_with_receipt};

#[test]
fn returns_literal_suffix_after_the_actual_anchor_and_restores_appendability() {
	let state = State::default();
	let (mut journal, start, expected, bytes) = chain(&state);
	let effects = (state.writes.get(), state.barriers.get());
	let mut output = [0xa5; 4096];
	let count = journal
		.confirm_current_suffix(&start, &expected, &mut output)
		.unwrap();
	assert_eq!(&output[..count], bytes);
	assert!(output[count..].iter().all(|&byte| byte == 0xa5));
	assert_eq!((state.writes.get(), state.barriers.get()), effects);
	let mut frames = FrameReader::new(&output[..count], start.head());
	for kind in [
		FrameKind::VerificationRecorded,
		FrameKind::MetadataRecorded,
		FrameKind::PublishIntent,
		FrameKind::PublishObserved,
		FrameKind::DurabilityRecorded,
		FrameKind::ReceiptCommitted,
	] {
		assert_eq!(frames.next_frame().unwrap().unwrap().kind(), kind);
	}
	assert_eq!(frames.head(), expected.head());
	assert!(frames.next_frame().unwrap().is_none());
	let next = journal.append(FrameKind::JobCheckpoint, b"later").unwrap();
	assert_eq!(next.head().sequence(), expected.head().sequence() + 1);
}

#[test]
fn a_terminal_anchor_returns_an_empty_suffix_after_true_eof() {
	let state = State::default();
	let (mut journal, _, expected, _) = chain(&state);
	assert_eq!(
		journal
			.confirm_current_suffix(&expected, &expected, &mut [])
			.unwrap(),
		0
	);
	assert!(state.reads.get() > 0);
}

#[test]
fn invalid_inputs_do_not_inspect_read_or_retire_the_writer() {
	let state = State::default();
	let (mut journal, start, expected, _) = chain(&state);
	state.refuse_inspect.set(true);
	let mut output = [0xa5; 4097];
	assert!(matches!(
		journal.confirm_current_suffix(&start, &expected, &mut output),
		Err(DurableJournalError::InvalidSuffixRequest)
	));
	assert!(matches!(
		journal.confirm_current_suffix(&start, &start, &mut output),
		Err(DurableJournalError::StaleExpectedHead)
	));
	let reversed = SyncedFrame {
		head: ChainHead::after(expected.head().sequence() + 1, [0x44; 32]).unwrap(),
		kind: FrameKind::StageSealed,
		barrier: expected.barrier(),
	};
	assert!(matches!(
		journal.confirm_current_suffix(&reversed, &expected, &mut output[..1]),
		Err(DurableJournalError::InvalidSuffixRequest)
	));
	assert_eq!(state.reads.get(), 0);
	assert_eq!(output, [0xa5; 4097]);
	state.refuse_inspect.set(false);
	journal.append(FrameKind::JobCheckpoint, b"usable").unwrap();
}

#[test]
fn missing_anchor_or_insufficient_output_retires_without_exposing_partial_bytes() {
	for missing in [false, true] {
		let state = State::default();
		let (mut journal, start, expected, _) = chain(&state);
		let effects = (state.writes.get(), state.barriers.get());
		let foreign = SyncedFrame {
			head: ChainHead::after(start.head().sequence(), [0x77; 32]).unwrap(),
			kind: start.kind(),
			barrier: start.barrier(),
		};
		let mut output = [0xa5; 4096];
		let result = if missing {
			journal.confirm_current_suffix(&foreign, &expected, &mut output)
		} else {
			journal.confirm_current_suffix(&start, &expected, &mut output[..1])
		};
		if missing {
			assert!(matches!(
				result,
				Err(DurableJournalError::SuffixAnchorNotFound)
			));
		} else {
			assert!(matches!(result, Err(DurableJournalError::SuffixTooLarge)));
		}
		assert_eq!(output, [0xa5; 4096]);
		assert!(matches!(
			journal.append(FrameKind::JobCheckpoint, b"no"),
			Err(DurableJournalError::Retired)
		));
		assert_eq!((state.writes.get(), state.barriers.get()), effects);
	}
}

#[test]
fn corruption_before_the_anchor_and_late_eof_growth_are_not_accepted() {
	for growth in [false, true] {
		let state = State::default();
		let (mut journal, start, expected, _) = chain(&state);
		if growth {
			state.extend_on_read.set(true);
		} else {
			journal.writer.as_mut().unwrap().sink_mut().cursor.get_mut()[0] ^= 1;
		}
		let mut output = [0xa5; 4096];
		let result = journal.confirm_current_suffix(&start, &expected, &mut output);
		if growth {
			assert!(matches!(
				result,
				Err(DurableJournalError::TrailingSuffixData { .. })
			));
		} else {
			assert!(matches!(
				result,
				Err(DurableJournalError::ReadFrame(FrameReadError::Corrupt {
					offset: 0,
					..
				}))
			));
		}
		assert_eq!(output, [0xa5; 4096]);
		assert!(matches!(
			journal.confirm_current_frame(&expected),
			Err(DurableJournalError::Retired)
		));
	}
}

#[test]
fn a_full_suffix_leaves_the_independent_eof_probe_outside_capture_capacity() {
	for growth in [false, true] {
		let state = State::default();
		let payload = vec![0x44; 4096 - 6 * FRAME_OVERHEAD_BYTES - 5];
		let (mut journal, start, expected, bytes) = chain_with_receipt(&state, &payload);
		assert_eq!(bytes.len(), 4096);
		let end = journal.end;
		state.extend_on_read.set(growth);
		let mut output = [0xa5; 4096];
		let result = journal.confirm_current_suffix(&start, &expected, &mut output);
		if growth {
			assert!(
				matches!(result, Err(DurableJournalError::TrailingSuffixData { offset }) if offset == end)
			);
			assert_eq!(output, [0xa5; 4096]);
			assert!(matches!(
				journal.confirm_current_frame(&expected),
				Err(DurableJournalError::Retired)
			));
		} else {
			assert_eq!(result.unwrap(), 4096);
			assert_eq!(output.as_slice(), bytes);
		}
	}
}

#[test]
fn the_actual_terminal_kind_must_match_the_selected_token() {
	let state = State::default();
	let (mut journal, start, expected, _) = chain(&state);
	let wrong_kind = SyncedFrame {
		head: expected.head(),
		kind: FrameKind::StageSealed,
		barrier: expected.barrier(),
	};
	let mut output = [0xa5; 4096];
	assert!(matches!(
		journal.confirm_current_suffix(&start, &wrong_kind, &mut output),
		Err(DurableJournalError::UnexpectedHead)
	));
	assert_eq!(output, [0xa5; 4096]);
	assert!(matches!(
		journal.confirm_current_frame(&expected),
		Err(DurableJournalError::Retired)
	));
}

#[test]
fn all_framed_reads_and_the_terminal_probe_share_one_interruption_budget() {
	for eof_count in [8, 9] {
		let state = State::default();
		let (mut journal, start, expected, bytes) = chain(&state);
		state.interrupts.set(8);
		state.eof_interrupts.set(eof_count);
		let mut output = [0xa5; 4096];
		let result = journal.confirm_current_suffix(&start, &expected, &mut output);
		if eof_count == 8 {
			let length = result.unwrap();
			assert_eq!(&output[..length], bytes);
		} else {
			let Err(DurableJournalError::ReadFrame(FrameReadError::Io { source, .. })) = result
			else {
				panic!("expected a terminal interrupted EOF refusal")
			};
			assert_eq!(source.kind(), io::ErrorKind::Other);
			assert_eq!(
				source
					.get_ref()
					.unwrap()
					.downcast_ref::<io::Error>()
					.unwrap()
					.kind(),
				io::ErrorKind::Interrupted
			);
			assert_eq!(output, [0xa5; 4096]);
			assert!(matches!(
				journal.confirm_current_frame(&expected),
				Err(DurableJournalError::Retired)
			));
		}
	}
}

#[test]
fn eof_failure_or_failed_cursor_restore_preserves_output_and_retires() {
	for restore in [false, true] {
		let state = State::default();
		let (mut journal, start, expected, _) = chain(&state);
		if restore {
			state.refuse_restore.set(true);
		} else {
			state.refuse_eof.set(true);
		}
		let mut output = [0xa5; 4096];
		let result = journal.confirm_current_suffix(&start, &expected, &mut output);
		if restore {
			assert!(matches!(result, Err(DurableJournalError::Inspect(_))));
		} else {
			assert!(matches!(
				result,
				Err(DurableJournalError::ReadFrame(FrameReadError::Io { .. }))
			));
		}
		assert_eq!(output, [0xa5; 4096]);
		assert!(matches!(
			journal.confirm_current_frame(&expected),
			Err(DurableJournalError::Retired)
		));
	}
}
