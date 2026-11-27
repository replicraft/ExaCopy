use std::num::NonZeroU64;

use exacopy_model::retained_prefix::Head;

use super::{WitnessObservationAppend, WitnessReservationPlan, matches_bounds};

#[test]
fn observation_requires_a_payload_nonzero_digest_and_an_unspent_frame_slot() {
	let previous = Head {
		digest: [7; 32],
		sequence: 7,
		end: 1200,
	};
	let reserve_end = 2200;
	let room =
		WitnessReservationPlan::new(previous, reserve_end, NonZeroU64::new(2).unwrap()).unwrap();
	let no_slot = WitnessReservationPlan::new(previous, reserve_end, NonZeroU64::MIN).unwrap();
	// The framing contract adds 92 bytes before any outcome payload.
	let overhead = 92;
	let mut record = WitnessObservationAppend {
		previous,
		successor: Head {
			digest: [8; 32],
			sequence: 8,
			end: previous.end + 93,
		},
		encoded: vec![0; overhead + 1],
	};
	assert!(matches_bounds(room, &record));
	assert!(!matches_bounds(no_slot, &record));

	let digest = record.successor.digest;
	record.successor.digest = [0; 32];
	assert!(!matches_bounds(room, &record));

	record.successor.digest = digest;
	record.successor.end -= 1;
	record.encoded.truncate(overhead);
	assert!(!matches_bounds(room, &record));
}
