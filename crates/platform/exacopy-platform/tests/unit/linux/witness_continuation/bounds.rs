use std::num::NonZeroU64;
use std::ops::Range;

use exacopy_model::retained_prefix::Head;

use super::super::{WitnessReservationPlan, checkpoints::matches_checkpoint, matches_next_frame};

const PRIOR: Head = Head {
	digest: [0x12; 32],
	sequence: 7,
	end: 1_000,
};
const SUCCESSOR_DIGEST: [u8; 32] = [0x34; 32];
const FRAME_LIMIT: usize = 1_116;
const SEGMENT_BOUND: u64 = 3_000;

fn plan(reserve_end: u64, frames: u64) -> WitnessReservationPlan {
	WitnessReservationPlan::new(PRIOR, reserve_end, NonZeroU64::new(frames).unwrap()).unwrap()
}

fn next(previous: Head, width: usize) -> Head {
	Head {
		digest: SUCCESSOR_DIGEST,
		sequence: previous.sequence + 1,
		end: previous.end + u64::try_from(width).unwrap(),
	}
}

#[test]
fn continuation_requires_an_exact_positive_bounded_successor_and_closing_space() {
	let available = plan(SEGMENT_BOUND, 3);
	for width in [1, FRAME_LIMIT] {
		assert!(matches_next_frame(
			available,
			PRIOR,
			next(PRIOR, width),
			width,
		));
	}
	for width in [0, FRAME_LIMIT + 1] {
		assert!(!matches_next_frame(
			available,
			PRIOR,
			next(PRIOR, width),
			width,
		));
	}

	let candidate = next(PRIOR, FRAME_LIMIT);
	assert!(matches_next_frame(
		plan(candidate.end + 1, 3),
		PRIOR,
		candidate,
		FRAME_LIMIT,
	));
	assert!(!matches_next_frame(
		plan(candidate.end, 3),
		PRIOR,
		candidate,
		FRAME_LIMIT,
	));

	assert!(matches_next_frame(
		plan(SEGMENT_BOUND, 2),
		PRIOR,
		candidate,
		FRAME_LIMIT,
	));
	assert!(!matches_next_frame(
		plan(SEGMENT_BOUND, 1),
		PRIOR,
		candidate,
		FRAME_LIMIT,
	));

	for wrong in [
		Head {
			end: candidate.end - 1,
			..candidate
		},
		Head {
			end: candidate.end + 1,
			..candidate
		},
		Head {
			sequence: PRIOR.sequence,
			..candidate
		},
		Head {
			sequence: candidate.sequence + 1,
			..candidate
		},
		Head {
			digest: [0; 32],
			..candidate
		},
		Head {
			digest: PRIOR.digest,
			..candidate
		},
	] {
		assert!(
			!matches_next_frame(available, PRIOR, wrong, FRAME_LIMIT),
			"{wrong:?}"
		);
	}
}

#[test]
fn checkpoint_cannot_skip_or_repeat_stage_bytes_or_spend_the_terminal_slot() {
	const CONFIRMED: u64 = 4_096;
	const NEXT_END: u64 = 8_192;
	const CHECKPOINT_WIDTH: usize = 860;
	let previous = next(PRIOR, FRAME_LIMIT);
	let checkpoint = Head {
		digest: [0x56; 32],
		..next(previous, CHECKPOINT_WIDTH)
	};
	let check = |frames, range: &Range<u64>| {
		matches_checkpoint(
			plan(SEGMENT_BOUND, frames),
			previous,
			checkpoint,
			CHECKPOINT_WIDTH,
			CONFIRMED,
			range,
		)
	};
	assert!(check(3, &(CONFIRMED..NEXT_END)));
	assert!(!check(2, &(CONFIRMED..NEXT_END)));
	for bad_range in [
		CONFIRMED + 1..NEXT_END,
		CONFIRMED - 1..NEXT_END,
		CONFIRMED..CONFIRMED,
		Range {
			start: CONFIRMED,
			end: CONFIRMED - 1,
		},
	] {
		assert!(!check(3, &bad_range), "{bad_range:?}");
	}
}
