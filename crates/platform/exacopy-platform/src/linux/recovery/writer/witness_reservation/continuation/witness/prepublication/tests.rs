use std::num::NonZeroU64;

use exacopy_model::retained_prefix::Head;

use super::{
	NativePrepublication, WitnessPrepublicationAppend, WitnessPrepublicationPhase as Phase,
	WitnessReservationPlan, matches_successor,
};

#[test]
fn exact_phase_order_and_terminal_states_refuse_other_intents() {
	let mut next = NativePrepublication::FIRST;
	for phase in [Phase::Seal, Phase::Verify, Phase::Metadata, Phase::Intent] {
		for probe in [Phase::Seal, Phase::Verify, Phase::Metadata, Phase::Intent] {
			assert_eq!(next.check(probe).is_ok(), probe == phase);
			assert!(NativePrepublication::Uncertain.check(probe).is_err());
			assert!(NativePrepublication::IntentSynced.check(probe).is_err());
		}
		next = phase.after();
	}
	assert!(matches!(next, NativePrepublication::IntentSynced));
}

#[test]
fn exact_successor_caps_and_remaining_capacity_are_checked() {
	let previous = Head {
		digest: [1; 32],
		sequence: 6,
		end: 300,
	};
	let successor = Head {
		digest: [2; 32],
		sequence: 7,
		end: 935,
	};
	let plan = WitnessReservationPlan::new(previous, 1400, NonZeroU64::new(3).unwrap()).unwrap();
	let encoded = [0; 635];
	let proposed = WitnessPrepublicationAppend {
		previous,
		successor,
		encoded: &encoded,
	};
	assert!(matches_successor(plan, Phase::Seal, proposed));
	assert!(!matches_successor(plan, Phase::Verify, proposed));
	assert!(!matches_successor(plan, Phase::Metadata, proposed));
	let short = WitnessReservationPlan::new(previous, 935, NonZeroU64::new(3).unwrap()).unwrap();
	assert!(!matches_successor(short, Phase::Seal, proposed));
	let skipped = Head {
		sequence: 8,
		..successor
	};
	let alias = Head {
		digest: previous.digest,
		..successor
	};
	let overrun = Head {
		end: successor.end + 1,
		..successor
	};
	for malformed in [skipped, alias, overrun] {
		assert!(!matches_successor(
			plan,
			Phase::Seal,
			WitnessPrepublicationAppend {
				successor: malformed,
				..proposed
			}
		));
	}
}
