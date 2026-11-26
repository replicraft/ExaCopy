//! Retained-prefix ordering, scope and append-range regressions.

use core::num::NonZeroU64;

use exacopy_model::retained_prefix::{
	BudgetReservation, Checkpoint, Continuation, Guard, Head, History, Live, Pass, PrefixProof,
	Prior, Refusal, TailWrite,
};

const fn nz(value: u64) -> NonZeroU64 {
	NonZeroU64::new(value).expect("fixture labels are nonzero")
}

const GUARD: Guard = Guard {
	authority: [1; 32],
	stage: [2; 32],
	lease: [3; 32],
};
const fn head(digest: u8, sequence: u64, end: u64) -> Head {
	Head {
		digest: [digest; 32],
		sequence,
		end,
	}
}

const OLD: Head = head(4, 2, 256);
const NEW: Head = head(5, 3, 512);
const FIRST_CHECKPOINT: Head = head(6, 4, 768);
const SECOND_CHECKPOINT: Head = head(7, 5, 1024);

const fn checkpoint(predecessor: Head, current: Head, start: u64, end: u64) -> Checkpoint {
	Checkpoint {
		lineage: NEW,
		predecessor,
		ordinal: if predecessor.sequence == NEW.sequence {
			1
		} else {
			2
		},
		head: current,
		pass: PASS,
		guard: GUARD,
		start,
		end,
	}
}

#[path = "retained_prefix/budgets.rs"]
mod budgets;
use budgets::TailFixture;

#[path = "retained_prefix/checkpoints.rs"]
mod checkpoints;
const PRIOR: Prior = Prior {
	guard: GUARD,
	head: OLD,
	preparation: head(8, 1, 128),
	pass: Pass {
		run: nz(2),
		source: nz(5),
	},
	checkpoint_end: 2,
	authorized_end: 5,
	history: History::CleanCapture,
	writer_quiesced: true,
};
const PASS: Pass = Pass {
	run: nz(3),
	source: nz(9),
};
const PROOF: PrefixProof = PrefixProof {
	local_end: 3,
	compared_end: 3,
	rehashed_end: 2,
	digest: [7; 32],
};
const EXTENT: u64 = 6;

const fn live(head: Head, local_end: u64) -> Live {
	Live {
		guard: GUARD,
		head,
		source: PASS.source,
		local_end,
	}
}

fn session() -> Continuation {
	Continuation::begin(PRIOR, PASS, PROOF, EXTENT).expect("valid initial evidence")
}

fn continued() -> Continuation {
	let mut value = session();
	value.prefix_barrier(live(OLD, 3), value.basis()).unwrap();
	value.continued(live(NEW, 3), value.basis(), NEW).unwrap();
	value
}

#[test]
fn retained_prefix_requires_ordered_evidence_and_exact_tail_completions() {
	let mut model = session();
	assert_eq!(
		model.permit_fixture_tail(live(OLD, 3), 3, 1),
		Err(Refusal::Order)
	);
	assert_eq!(
		model.continued(live(NEW, 3), model.basis(), NEW),
		Err(Refusal::Order)
	);
	model.prefix_barrier(live(OLD, 3), model.basis()).unwrap();
	assert_eq!(
		model.permit_fixture_tail(live(OLD, 3), 3, 1),
		Err(Refusal::Order)
	);
	model.continued(live(NEW, 3), model.basis(), NEW).unwrap();
	for (offset, length) in [(0, 1), (2, 1), (4, 1), (3, 0), (3, 4), (3, u64::MAX)] {
		assert_eq!(
			model.permit_fixture_tail(live(NEW, 3), offset, length),
			Err(Refusal::Range)
		);
	}
	let one = model.permit_fixture_tail(live(NEW, 3), 3, 1).unwrap();
	assert_eq!(one.range(), 3..4);
	assert_eq!(
		model.permit_fixture_tail(live(NEW, 3), 3, 1),
		Err(Refusal::Order)
	);
	model.complete_tail(live(NEW, 4), one).unwrap();
	assert_eq!(
		model.permit_fixture_tail(live(NEW, 4), 4, 1),
		Err(Refusal::Order)
	);
	model
		.checkpoint(
			live(FIRST_CHECKPOINT, 4),
			checkpoint(NEW, FIRST_CHECKPOINT, 3, 4),
		)
		.unwrap();
	assert_eq!(
		model.permit_fixture_tail(live(FIRST_CHECKPOINT, 4), 3, 1),
		Err(Refusal::Range)
	);
	let two = model
		.permit_fixture_tail(live(FIRST_CHECKPOINT, 4), 4, 2)
		.unwrap();
	assert_eq!(two.range(), 4..6);
	model.complete_tail(live(FIRST_CHECKPOINT, 6), two).unwrap();
	model
		.checkpoint(
			live(SECOND_CHECKPOINT, 6),
			checkpoint(FIRST_CHECKPOINT, SECOND_CHECKPOINT, 4, 6),
		)
		.unwrap();
	assert_eq!(
		model.permit_fixture_tail(live(SECOND_CHECKPOINT, 6), 6, 1),
		Err(Refusal::Range)
	);
}

#[test]
fn refuses_each_incomplete_history_freshness_and_prefix_witness() {
	for (prior, pass, proof, extent, refusal) in [
		(
			Prior {
				history: History::Uncertain,
				..PRIOR
			},
			PASS,
			PROOF,
			EXTENT,
			Refusal::History,
		),
		(
			Prior {
				history: History::PostIntent,
				..PRIOR
			},
			PASS,
			PROOF,
			EXTENT,
			Refusal::History,
		),
		(
			Prior {
				writer_quiesced: false,
				..PRIOR
			},
			PASS,
			PROOF,
			EXTENT,
			Refusal::History,
		),
		(
			PRIOR,
			Pass {
				source: PRIOR.pass.source,
				..PASS
			},
			PROOF,
			EXTENT,
			Refusal::Pass,
		),
		(
			PRIOR,
			Pass { run: nz(4), ..PASS },
			PROOF,
			EXTENT,
			Refusal::Pass,
		),
		(
			Prior {
				pass: Pass {
					run: nz(u64::MAX),
					..PRIOR.pass
				},
				..PRIOR
			},
			PASS,
			PROOF,
			EXTENT,
			Refusal::Pass,
		),
		(
			Prior {
				checkpoint_end: 0,
				..PRIOR
			},
			PASS,
			PROOF,
			EXTENT,
			Refusal::Prefix,
		),
		(
			PRIOR,
			PASS,
			PrefixProof {
				rehashed_end: 1,
				..PROOF
			},
			EXTENT,
			Refusal::Prefix,
		),
		(
			PRIOR,
			PASS,
			PrefixProof {
				compared_end: 2,
				..PROOF
			},
			EXTENT,
			Refusal::Prefix,
		),
		(
			PRIOR,
			PASS,
			PrefixProof {
				compared_end: 1,
				local_end: 1,
				..PROOF
			},
			EXTENT,
			Refusal::Prefix,
		),
		(
			Prior {
				authorized_end: 2,
				..PRIOR
			},
			PASS,
			PROOF,
			EXTENT,
			Refusal::Prefix,
		),
		(PRIOR, PASS, PROOF, 2, Refusal::Prefix),
		(PRIOR, PASS, PROOF, u64::MAX, Refusal::Prefix),
	] {
		assert_eq!(
			Continuation::begin(prior, pass, proof, extent).unwrap_err(),
			refusal
		);
	}
	let limit = 64 * 1024 * 1024 + PRIOR.checkpoint_end;
	assert!(
		Continuation::begin(
			Prior {
				authorized_end: limit + 1,
				..PRIOR
			},
			PASS,
			PrefixProof {
				compared_end: limit,
				local_end: limit,
				..PROOF
			},
			limit + 1
		)
		.is_ok()
	);
	assert_eq!(
		Continuation::begin(
			Prior {
				authorized_end: limit + 1,
				..PRIOR
			},
			PASS,
			PrefixProof {
				compared_end: limit + 1,
				local_end: limit + 1,
				..PROOF
			},
			limit + 2
		)
		.unwrap_err(),
		Refusal::Prefix
	);
}

#[test]
fn binding_changes_and_uncertain_effects_latch_without_another_permit() {
	let basis = |model: &Continuation| model.basis();
	for bad in [
		Live {
			guard: Guard {
				stage: [8; 32],
				..GUARD
			},
			..live(OLD, 3)
		},
		Live {
			guard: Guard {
				lease: [8; 32],
				..GUARD
			},
			..live(OLD, 3)
		},
		Live {
			guard: Guard {
				authority: [8; 32],
				..GUARD
			},
			..live(OLD, 3)
		},
		live(NEW, 3),
		live(OLD, 4),
		Live {
			source: PRIOR.pass.source,
			..live(OLD, 3)
		},
	] {
		let mut value = session();
		assert_eq!(
			value.prefix_barrier(bad, basis(&value)),
			Err(Refusal::Binding)
		);
		assert_eq!(
			value.prefix_barrier(live(OLD, 3), basis(&value)),
			Err(Refusal::Order)
		);
	}
	let foreign = Continuation::begin(
		PRIOR,
		PASS,
		PrefixProof {
			digest: [8; 32],
			..PROOF
		},
		EXTENT,
	)
	.unwrap()
	.basis();
	let mut before = session();
	assert_eq!(
		before.prefix_barrier(live(OLD, 3), foreign),
		Err(Refusal::Evidence)
	);
	let mut after = session();
	after.prefix_barrier(live(OLD, 3), basis(&after)).unwrap();
	assert_eq!(
		after.continued(live(NEW, 3), foreign, NEW),
		Err(Refusal::Evidence)
	);
	let mut unchanged = session();
	unchanged
		.prefix_barrier(live(OLD, 3), basis(&unchanged))
		.unwrap();
	assert_eq!(
		unchanged.continued(live(OLD, 3), basis(&unchanged), OLD),
		Err(Refusal::Evidence)
	);

	let mut during = continued();
	let permit = during.permit_fixture_tail(live(NEW, 3), 3, 1).unwrap();
	during.block();
	assert_eq!(
		during.complete_tail(live(NEW, 4), permit),
		Err(Refusal::Order)
	);
	assert_eq!(
		during.permit_fixture_tail(live(NEW, 3), 3, 1),
		Err(Refusal::Order)
	);
}

#[test]
fn stale_completion_requires_reconciliation_before_any_further_progress() {
	let mut old = session();
	old.prefix_barrier(live(OLD, 3), old.basis()).unwrap();
	let older_head = head(9, NEW.sequence, NEW.end);
	old.continued(live(older_head, 3), old.basis(), older_head)
		.unwrap();
	let stale = old.permit_fixture_tail(live(older_head, 3), 3, 1).unwrap();
	let mut current = continued();
	let actual = current.permit_fixture_tail(live(NEW, 3), 3, 1).unwrap();
	assert_eq!(
		current.complete_tail(live(NEW, 4), stale),
		Err(Refusal::Completion)
	);
	assert_eq!(
		current.permit_fixture_tail(live(NEW, 4), 4, 1),
		Err(Refusal::Order)
	);
	assert_eq!(
		current.complete_tail(live(NEW, 4), actual),
		Err(Refusal::Order)
	);
	assert_eq!(
		current.permit_fixture_tail(live(NEW, 3), 3, 1),
		Err(Refusal::Order)
	);

	let mut stale_source = continued();
	let actual = stale_source
		.permit_fixture_tail(live(NEW, 3), 3, 1)
		.unwrap();
	assert_eq!(
		stale_source.complete_tail(
			Live {
				source: PRIOR.pass.source,
				..live(NEW, 4)
			},
			actual
		),
		Err(Refusal::Binding)
	);
	assert_eq!(
		stale_source.permit_fixture_tail(live(NEW, 4), 4, 1),
		Err(Refusal::Order)
	);
}

#[test]
fn unexpected_completion_blocks_even_without_a_pending_write() {
	let mut model = continued();
	let mut foreign = continued();
	let unissued = foreign.permit_fixture_tail(live(NEW, 3), 3, 1).unwrap();
	assert_eq!(
		model.complete_tail(live(NEW, 4), unissued),
		Err(Refusal::Completion)
	);
	assert_eq!(
		model.permit_fixture_tail(live(NEW, 3), 3, 1),
		Err(Refusal::Order)
	);
}
