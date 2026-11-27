use super::budgets::budget;
use super::*;

#[test]
fn continuation_rejects_a_zero_end_predecessor() {
	let old = Head { end: 0, ..OLD };
	let mut model = Continuation::begin(Prior { head: old, ..PRIOR }, PASS, PROOF, EXTENT)
		.expect("prefix evidence is complete");
	let basis = model.basis();
	model
		.prefix_barrier(live(old, 3), basis)
		.expect("barrier matches the selected prefix");
	assert_eq!(
		model.continued(live(NEW, 3), basis, NEW),
		Err(Refusal::Evidence)
	);
	assert_eq!(
		model.continued(live(NEW, 3), basis, NEW),
		Err(Refusal::Order)
	);
}

#[test]
fn closeout_can_use_the_last_byte_and_sequence_position_of_the_segment() {
	const SEGMENT_LIMIT: u64 = 64 * 1024 * 1024;
	const SOURCE_END: u64 = 4;
	// Fixture frames are 256 bytes, with 1024 bytes and four sequence slots for closeout.
	let old = Head {
		sequence: u64::MAX - 6,
		end: SEGMENT_LIMIT - 1536,
		..OLD
	};
	let next = Head {
		sequence: u64::MAX - 5,
		end: SEGMENT_LIMIT - 1280,
		..NEW
	};
	let current = live(next, 3);
	let mut model = Continuation::begin(Prior { head: old, ..PRIOR }, PASS, PROOF, SOURCE_END)
		.expect("prefix evidence is complete");
	let basis = model.basis();
	model
		.prefix_barrier(live(old, 3), basis)
		.expect("barrier matches the selected prefix");
	model
		.continued(current, basis, next)
		.expect("continuation is the exact successor");

	let exact = budget(current, SOURCE_END);
	let mut oversized = exact;
	oversized.closing_bytes = nz(1025);
	assert_eq!(
		model.permit_tail(current, 3, 1, oversized),
		Err(Refusal::Budget)
	);
	oversized = exact;
	oversized.closing_frames = nz(5);
	assert_eq!(
		model.permit_tail(current, 3, 1, oversized),
		Err(Refusal::Budget)
	);
	let permit = model
		.permit_tail(current, 3, 1, exact)
		.expect("checkpoint and closeout fit exactly");
	assert_eq!(permit.range(), 3..SOURCE_END);
	model
		.complete_tail(live(next, SOURCE_END), permit)
		.expect("completion matches the issued range");

	let confirmed = Head {
		sequence: u64::MAX - 4,
		end: SEGMENT_LIMIT - 1024,
		..FIRST_CHECKPOINT
	};
	model
		.checkpoint(
			live(confirmed, SOURCE_END),
			Checkpoint {
				lineage: next,
				predecessor: next,
				ordinal: 1,
				head: confirmed,
				pass: PASS,
				guard: GUARD,
				start: 3,
				end: SOURCE_END,
			},
		)
		.expect("checkpoint matches the exact reserved budget");
}
