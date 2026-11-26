use super::*;

#[test]
fn rejects_nonadjacent_or_wrongly_bound_confirmed_checkpoints() {
	let good = checkpoint(NEW, FIRST_CHECKPOINT, 3, 4);
	for invalid in [
		Checkpoint {
			lineage: OLD,
			..good
		},
		Checkpoint {
			predecessor: OLD,
			..good
		},
		Checkpoint {
			head: head(6, 5, 768),
			..good
		},
		Checkpoint {
			head: head(6, 4, NEW.end),
			..good
		},
		Checkpoint {
			head: head(6, 4, 64 * 1024 * 1024 + 1),
			..good
		},
		Checkpoint {
			head: head(5, 4, 768),
			..good
		},
		Checkpoint {
			head: head(0, 4, 768),
			..good
		},
		Checkpoint {
			pass: PRIOR.pass,
			..good
		},
		Checkpoint {
			guard: Guard {
				lease: [31; 32],
				..GUARD
			},
			..good
		},
		Checkpoint { start: 2, ..good },
		Checkpoint { end: 5, ..good },
		Checkpoint { ordinal: 2, ..good },
		Checkpoint {
			head: head(6, 4, 769),
			..good
		},
	] {
		let mut model = continued();
		let permit = model.permit_fixture_tail(live(NEW, 3), 3, 1).unwrap();
		model.complete_tail(live(NEW, 4), permit).unwrap();
		assert_eq!(
			model.checkpoint(live(invalid.head, 4), invalid),
			Err(Refusal::Evidence)
		);
		assert_eq!(
			model.permit_fixture_tail(live(NEW, 4), 4, 1),
			Err(Refusal::Order)
		);
	}
}

#[test]
fn checkpoint_cannot_cross_an_in_flight_write_and_old_head_cannot_issue_next_permit() {
	let mut model = continued();
	let permit = model.permit_fixture_tail(live(NEW, 3), 3, 1).unwrap();
	let record = checkpoint(NEW, FIRST_CHECKPOINT, 3, 4);
	assert_eq!(
		model.checkpoint(live(FIRST_CHECKPOINT, 3), record),
		Err(Refusal::Order)
	);
	model.complete_tail(live(NEW, 4), permit).unwrap();
	model.checkpoint(live(FIRST_CHECKPOINT, 4), record).unwrap();
	assert_eq!(
		model.permit_fixture_tail(live(NEW, 4), 4, 1),
		Err(Refusal::Binding)
	);
	assert_eq!(
		model.permit_fixture_tail(live(FIRST_CHECKPOINT, 4), 4, 1),
		Err(Refusal::Order)
	);
}

#[test]
fn partial_completion_fences_the_writer() {
	let mut model = continued();
	let permit = model.permit_fixture_tail(live(NEW, 3), 3, 2).unwrap();
	assert_eq!(
		model.complete_tail(live(NEW, 4), permit),
		Err(Refusal::Binding)
	);
	assert_eq!(
		model.permit_fixture_tail(live(NEW, 4), 4, 1),
		Err(Refusal::Order)
	);
}
