use std::num::NonZeroU64;

use exacopy_model::retained_prefix::Head;

use super::{
	MAX_OBSERVATION_FRAME, WitnessObservationAppend, WitnessReservationPlan, matches_bounds,
};

#[test]
fn exact_outcome_width_and_same_segment_head_are_required() {
	let previous = Head {
		digest: [1; 32],
		sequence: 8,
		end: 1200,
	};
	let plan = WitnessReservationPlan::new(previous, 2200, NonZeroU64::new(4).unwrap()).unwrap();
	let successor = Head {
		digest: [2; 32],
		sequence: 9,
		end: 1200 + MAX_OBSERVATION_FRAME as u64,
	};
	let mut record = WitnessObservationAppend {
		previous,
		successor,
		encoded: vec![0; MAX_OBSERVATION_FRAME],
	};
	assert!(matches_bounds(plan, &record));
	record.successor.sequence += 1;
	assert!(!matches_bounds(plan, &record));
	record.successor = Head {
		digest: previous.digest,
		..successor
	};
	assert!(!matches_bounds(plan, &record));
	record.successor = Head {
		end: successor.end + 1,
		..successor
	};
	record.encoded.push(0);
	assert!(!matches_bounds(plan, &record));
	record.encoded.pop();
	assert!(!matches_bounds(plan, &record));
	record.successor = successor;
	let no_room =
		WitnessReservationPlan::new(previous, successor.end, NonZeroU64::new(4).unwrap()).unwrap();
	assert!(!matches_bounds(no_room, &record));
}
