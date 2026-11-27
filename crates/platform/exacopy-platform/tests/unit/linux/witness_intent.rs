use std::num::NonZeroU64;

use exacopy_model::retained_prefix::Head;

use super::{WitnessReservationPlan, fits_witness_intent};

const PREVIOUS: Head = Head {
	digest: [0x21; 32],
	sequence: 8,
	end: 1_000,
};
const SUCCESSOR: Head = Head {
	digest: [0x34; 32],
	sequence: 9,
	end: 1_697,
};
const KIND_41_MAX: usize = 697;

#[test]
fn witness_intent_bounds_distinguish_exact_wire_and_reservation_limits() {
	let reserve_frames = NonZeroU64::new(2).expect("two slots include remaining capacity");
	let plan = WitnessReservationPlan::new(PREVIOUS, 1_698, reserve_frames)
		.expect("valid reservation with one byte and slot left after the successor");
	assert!(fits_witness_intent(plan, PREVIOUS, SUCCESSOR, KIND_41_MAX));

	// The platform predicate owns a positive width and ceiling. Semantic framing
	// and authentication are checked by application replay.
	let roomy = WitnessReservationPlan::new(PREVIOUS, 2_000, reserve_frames)
		.expect("width is isolated from reservation exhaustion");
	for (width, end, accepted) in [(0, 1_000, false), (1, 1_001, true), (698, 1_698, false)] {
		assert_eq!(
			fits_witness_intent(roomy, PREVIOUS, Head { end, ..SUCCESSOR }, width),
			accepted,
			"kind 41 encoded width {width}",
		);
	}

	let exhausted_bytes = WitnessReservationPlan::new(PREVIOUS, SUCCESSOR.end, reserve_frames)
		.expect("valid plan whose byte ceiling equals the proposed successor");
	let exhausted_slots = WitnessReservationPlan::new(PREVIOUS, 1_698, NonZeroU64::MIN)
		.expect("valid plan whose sequence ceiling equals the proposed successor");
	for (boundary, plan) in [("byte", exhausted_bytes), ("sequence", exhausted_slots)] {
		assert!(
			!fits_witness_intent(plan, PREVIOUS, SUCCESSOR, KIND_41_MAX),
			"kind 41 consumed the exclusive {boundary} ceiling",
		);
	}
}

#[test]
fn witness_intent_bounds_reject_unrelated_or_overflowed_successors() {
	let plan = WitnessReservationPlan::new(
		PREVIOUS,
		2_000,
		NonZeroU64::new(3).expect("permit testing a sequence gap inside the reserve"),
	)
	.expect("valid reservation with capacity beyond each tested successor");
	for (case, previous, successor) in [
		(
			"wrong end",
			PREVIOUS,
			Head {
				end: 1_696,
				..SUCCESSOR
			},
		),
		(
			"skipped sequence",
			PREVIOUS,
			Head {
				sequence: 10,
				..SUCCESSOR
			},
		),
		(
			"zero digest",
			PREVIOUS,
			Head {
				digest: [0; 32],
				..SUCCESSOR
			},
		),
		(
			"repeated digest",
			PREVIOUS,
			Head {
				digest: PREVIOUS.digest,
				..SUCCESSOR
			},
		),
		(
			"overflowed end",
			Head {
				end: u64::MAX,
				..PREVIOUS
			},
			Head {
				end: 696,
				..SUCCESSOR
			},
		),
		(
			"overflowed sequence",
			Head {
				sequence: u64::MAX,
				..PREVIOUS
			},
			Head {
				sequence: 0,
				..SUCCESSOR
			},
		),
	] {
		assert!(
			!fits_witness_intent(plan, previous, successor, KIND_41_MAX),
			"kind 41 admitted {case}",
		);
	}
}
