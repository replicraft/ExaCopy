use std::num::NonZeroU64;

use exacopy_model::retained_prefix::Head;

use super::{
	MAX_DURABILITY_FRAME, WitnessDurabilityAppend, WitnessReservationPlan, matches_bounds,
};

#[test]
fn exact_durability_width_and_same_segment_head_are_required() {
	let previous = Head {
		digest: [1; 32],
		sequence: 8,
		end: 1200,
	};
	let plan = WitnessReservationPlan::new(previous, 2200, NonZeroU64::new(4).unwrap()).unwrap();
	let successor = Head {
		digest: [2; 32],
		sequence: 9,
		end: 1200 + MAX_DURABILITY_FRAME as u64,
	};
	let mut record = WitnessDurabilityAppend {
		previous,
		successor,
		encoded: vec![0; MAX_DURABILITY_FRAME],
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

#[test]
fn durability_requires_nonempty_identity_and_a_later_reserved_slot() {
	let previous = Head {
		digest: [8; 32],
		sequence: 8,
		end: 1200,
	};
	let room = WitnessReservationPlan::new(previous, 2200, NonZeroU64::new(2).unwrap()).unwrap();
	let final_slot = WitnessReservationPlan::new(previous, 2200, NonZeroU64::MIN).unwrap();
	// A 92-byte envelope requires a nonempty payload. Leave one later sequence
	// position for subsequent closeout even when the byte reservation has room.
	let mut proposed = WitnessDurabilityAppend {
		previous,
		successor: Head {
			digest: [9; 32],
			sequence: 9,
			end: 1293,
		},
		encoded: vec![0; 93],
	};
	assert!(matches_bounds(room, &proposed));
	assert!(!matches_bounds(final_slot, &proposed));

	proposed.successor.digest = [0; 32];
	assert!(!matches_bounds(room, &proposed));

	proposed.successor.digest = [9; 32];
	proposed.successor.end = 1292;
	proposed.encoded.truncate(92);
	assert!(!matches_bounds(room, &proposed));
}

#[test]
fn classifies_probe_refusal_separately_from_a_submitted_barrier_error() {
	use super::{StageError, WitnessDurabilityEffect, WitnessDurabilityError, barrier_failure};

	let effect = WitnessDurabilityEffect::DestinationDirectory;
	assert!(matches!(
		barrier_failure::<()>(effect, StageError::IdentityChanged),
		WitnessDurabilityError::BarrierPreflight {
			effect: WitnessDurabilityEffect::DestinationDirectory,
			cause: StageError::IdentityChanged,
		},
	));
	let failure = std::io::ErrorKind::WriteZero;
	assert!(matches!(
		barrier_failure::<()>(effect, StageError::DirectoryBarrierFailed(failure.into())),
		WitnessDurabilityError::BarrierSubmitted {
			effect: WitnessDurabilityEffect::DestinationDirectory,
			cause: StageError::DirectoryBarrierFailed(cause),
		} if cause.kind() == failure
	));
	assert!(matches!(
		barrier_failure::<()>(
			WitnessDurabilityEffect::File,
			StageError::BarrierFailed(failure.into()),
		),
		WitnessDurabilityError::BarrierSubmitted {
			effect: WitnessDurabilityEffect::File,
			cause: StageError::BarrierFailed(cause),
		} if cause.kind() == failure
	));
}
