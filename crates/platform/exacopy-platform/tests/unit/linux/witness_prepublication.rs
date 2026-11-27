use std::num::NonZeroU64;

use exacopy_model::retained_prefix::Head;

use super::{
	WitnessPrepublicationAppend, WitnessPrepublicationPhase as Phase, WitnessReservationPlan,
	matches_successor,
};

#[test]
fn prepublication_admits_exact_per_kind_widths_and_leaves_a_later_slot() {
	// Encoded widths come from the canonical contract table (payload + framing).
	const FRAMING_ONLY: u64 = 92;
	let previous = Head {
		digest: [0x21; 32],
		sequence: 8,
		end: 1_000,
	};
	let plan = WitnessReservationPlan::new(
		previous,
		3_000,
		NonZeroU64::new(2).expect("one later slot remains"),
	)
	.expect("valid reservation with space beyond each maximum encoded width");
	let last_slot = WitnessReservationPlan::new(previous, 3_000, NonZeroU64::MIN)
		.expect("valid reservation with no later slot");
	for (phase, max_width) in [
		(Phase::Seal, 635),
		(Phase::Verify, 567),
		(Phase::Metadata, 546),
		(Phase::Intent, 1_014),
	] {
		for (width, accepted) in [
			(FRAMING_ONLY, false),
			(FRAMING_ONLY + 1, true),
			(max_width, true),
			(max_width + 1, false),
		] {
			let successor = Head {
				digest: [0x34; 32],
				sequence: 9,
				end: previous.end + width,
			};
			let encoded = vec![0; usize::try_from(width).expect("small fixture width")];
			let proposed = WitnessPrepublicationAppend {
				previous,
				successor,
				encoded: &encoded,
			};
			assert_eq!(
				matches_successor(plan, phase, proposed),
				accepted,
				"{phase:?} encoded width {width}",
			);
			if accepted {
				assert!(
					!matches_successor(last_slot, phase, proposed),
					"{phase:?} consumed the last reserved slot",
				);
			}
		}
	}
}
