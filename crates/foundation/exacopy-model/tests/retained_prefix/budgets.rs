use super::*;

pub(super) const fn budget(live: Live, tail_end: u64) -> BudgetReservation {
	BudgetReservation {
		live,
		tail_end,
		checkpoint_end: live.head.end + 256,
		closing_bytes: nz(1024),
		closing_frames: nz(4),
		receipt_bytes: nz(512),
		receipt_capacity: 512,
	}
}

pub(super) trait TailFixture {
	fn permit_fixture_tail(
		&mut self,
		live: Live,
		offset: u64,
		length: u64,
	) -> Result<TailWrite, Refusal>;
}

impl TailFixture for Continuation {
	fn permit_fixture_tail(
		&mut self,
		live: Live,
		offset: u64,
		length: u64,
	) -> Result<TailWrite, Refusal> {
		self.permit_tail(
			live,
			offset,
			length,
			budget(live, offset.saturating_add(length)),
		)
	}
}

#[test]
fn rejects_every_unreserved_budget_without_issuing_a_write() {
	let mut model = continued();
	let current = live(NEW, 3);
	let good = budget(current, 4);
	for bad in [
		BudgetReservation {
			live: live(OLD, 3),
			..good
		},
		BudgetReservation {
			tail_end: 5,
			..good
		},
		BudgetReservation {
			checkpoint_end: NEW.end,
			..good
		},
		BudgetReservation {
			checkpoint_end: 64 * 1024 * 1024,
			..good
		},
		BudgetReservation {
			checkpoint_end: u64::MAX,
			..good
		},
		BudgetReservation {
			closing_frames: nz(u64::MAX),
			..good
		},
		BudgetReservation {
			receipt_capacity: 511,
			..good
		},
	] {
		assert_eq!(model.permit_tail(current, 3, 1, bad), Err(Refusal::Budget));
	}
	assert_eq!(
		model.permit_tail(current, 3, 1, good).unwrap().range(),
		3..4
	);
}

#[test]
fn last_possible_journal_head_cannot_authorize_a_tail() {
	let mut model = session();
	model.prefix_barrier(live(OLD, 3), model.basis()).unwrap();
	let full_head = head(5, NEW.sequence, 64 * 1024 * 1024);
	let current = live(full_head, 3);
	model.continued(current, model.basis(), full_head).unwrap();
	assert_eq!(
		model.permit_fixture_tail(current, 3, 1),
		Err(Refusal::Budget)
	);
}

#[test]
fn permits_fully_retained_source_but_refuses_every_tail_write() {
	let mut model = Continuation::begin(PRIOR, PASS, PROOF, PROOF.local_end).unwrap();
	model.prefix_barrier(live(OLD, 3), model.basis()).unwrap();
	let current = live(NEW, 3);
	model.continued(current, model.basis(), NEW).unwrap();
	assert_eq!(
		model.permit_fixture_tail(current, 3, 1),
		Err(Refusal::Range)
	);
	assert_eq!(
		model.permit_fixture_tail(current, 3, 0),
		Err(Refusal::Range)
	);
	assert_eq!(
		model.permit_fixture_tail(current, 2, 1),
		Err(Refusal::Range)
	);
}

#[test]
fn checkpoint_ordinal_cannot_exceed_the_profile_budget() {
	let mut model = Continuation::begin(PRIOR, PASS, PROOF, 4100).unwrap();
	model.prefix_barrier(live(OLD, 3), model.basis()).unwrap();
	model.continued(live(NEW, 3), model.basis(), NEW).unwrap();
	let mut predecessor = NEW;
	for ordinal in 1..=4096 {
		let start = 2 + u64::from(ordinal);
		let end = start + 1;
		let permit = model
			.permit_fixture_tail(live(predecessor, start), start, 1)
			.unwrap();
		model.complete_tail(live(predecessor, end), permit).unwrap();
		let next = head(
			if predecessor.digest == NEW.digest {
				6
			} else {
				5
			},
			predecessor.sequence + 1,
			predecessor.end + 256,
		);
		model
			.checkpoint(
				live(next, end),
				Checkpoint {
					ordinal,
					..checkpoint(predecessor, next, start, end)
				},
			)
			.unwrap();
		predecessor = next;
	}
	assert_eq!(
		model.permit_fixture_tail(live(predecessor, 4099), 4099, 1),
		Err(Refusal::Budget)
	);
}
