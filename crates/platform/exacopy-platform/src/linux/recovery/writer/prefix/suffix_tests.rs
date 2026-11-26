use std::cell::Cell;
use std::num::NonZeroU64;

use exacopy_model::retained_prefix::{
	BudgetReservation, Continuation, Guard, Head, History, Live, Pass, PrefixProof, Prior,
	TailWrite,
};

use super::{Fixture, PREFIX, ReadView, StageError, fs, inventory, selection};
use crate::linux::{SuffixEffect, SuffixError};

fn nonzero(value: u64) -> NonZeroU64 {
	NonZeroU64::new(value).unwrap()
}

fn issued_tail(length: u64) -> TailWrite {
	let start = PREFIX.len() as u64;
	let guard = Guard {
		authority: [1; 32],
		stage: [2; 32],
		lease: [3; 32],
	};
	let old = Head {
		digest: [4; 32],
		sequence: 10,
		end: 10_000,
	};
	let next = Head {
		digest: [5; 32],
		sequence: 11,
		end: 10_500,
	};
	let pass = Pass {
		run: nonzero(2),
		source: nonzero(2),
	};
	let prior = Prior {
		guard,
		head: old,
		preparation: old,
		pass: Pass {
			run: nonzero(1),
			source: nonzero(1),
		},
		checkpoint_end: start,
		authorized_end: start,
		history: History::CleanCapture,
		writer_quiesced: true,
	};
	let proof = PrefixProof {
		local_end: start,
		compared_end: start,
		rehashed_end: start,
		digest: [6; 32],
	};
	let mut state = Continuation::begin(prior, pass, proof, start + length).unwrap();
	let live = Live {
		guard,
		head: old,
		source: pass.source,
		local_end: start,
	};
	state.prefix_barrier(live, state.basis()).unwrap();
	let live = Live { head: next, ..live };
	state.continued(live, state.basis(), next).unwrap();
	state
		.permit_tail(
			live,
			start,
			length,
			BudgetReservation {
				live,
				tail_end: start + length,
				checkpoint_end: 11_000,
				closing_bytes: nonzero(2_000),
				closing_frames: nonzero(9),
				receipt_bytes: nonzero(6_144),
				receipt_capacity: 6_144,
			},
		)
		.unwrap()
}

#[test]
fn suffix_writes_only_after_barrier_and_admission_and_retains_the_original_guard() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let expected = selection(&inventory);
	let reader = lease.read_retained_prefix(&inventory, expected).unwrap();
	let base = PREFIX.len() as u64;
	let sync = || {
		reader
			.sync_adopted(base, |actual, effect| {
				assert_eq!(actual, expected);
				assert_eq!(effect, SuffixEffect::PrefixBarrier { end: base });
				Ok::<_, ()>(())
			})
			.unwrap()
	};
	let first = sync();
	assert!(matches!(
		reader.sync_adopted(base, |_, _| -> Result<(), ()> {
			panic!("second barrier reached gate")
		}),
		Err(SuffixError::Observation(_))
	));
	let mut writer = first
		.open_suffix_writer(base + 4, |actual, end| {
			assert_eq!(actual, expected);
			assert_eq!(end, base..base + 4);
			Ok::<_, ()>(())
		})
		.unwrap();
	assert!(writer.checkpoint_proof().is_err());
	let permit = issued_tail(4);
	writer.begin_range(&permit, |_| Ok::<_, ()>(())).unwrap();
	for (offset, data) in [(base, b"xy"), (base + 2, b"z!")] {
		writer
			.write_next(data, |actual, effect| {
				assert_eq!(actual, expected);
				assert_eq!(effect, SuffixEffect::Write { offset, length: 2 });
				Ok::<_, ()>(())
			})
			.unwrap();
	}
	assert_eq!(
		writer
			.sync_range(|_, effect| {
				assert_eq!(effect, SuffixEffect::CheckpointBarrier { end: base + 4 });
				Ok::<_, ()>(())
			})
			.unwrap(),
		base + 4
	);
	{
		let proof = writer.checkpoint_proof().unwrap();
		assert_eq!(proof.range(), &(base..base + 4));
		proof.check_for(&reader).unwrap();
	}

	writer
		.confirm_checkpoint(|end| {
			assert_eq!(end, base + 4);
			Ok::<_, ()>(())
		})
		.unwrap();
	let read = writer.finish().unwrap();
	let mut observed = vec![0; PREFIX.len() + 4];
	read.read_exact_at(0, &mut observed).unwrap();
	read.recheck_observation().unwrap();
	assert_eq!(&observed[..PREFIX.len()], PREFIX);
	assert_eq!(&observed[PREFIX.len()..], b"xyz!");
	assert!(matches!(
		lease.reopen_stage_directory(&inventory),
		Err(StageError::JobBusy)
	));
	assert!(!fixture.target().exists());
}

#[test]
fn boundary_failure_keeps_private_data_and_the_descriptor_cannot_skip_the_range() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let expected = selection(&inventory);
	let reader = lease.read_retained_prefix(&inventory, expected).unwrap();
	let base = PREFIX.len() as u64;
	let attempted = Cell::new(0);
	fs::write(fixture.target(), b"incumbent").unwrap();
	assert!(matches!(
		reader.sync_adopted(base, |_, _| {
			attempted.set(attempted.get() + 1);
			Ok::<_, ()>(())
		}),
		Err(SuffixError::Observation(_))
	));
	assert_eq!(attempted.get(), 0);
	assert_eq!(fs::read(fixture.target()).unwrap(), b"incumbent");
	fs::remove_file(fixture.target()).unwrap();
	let mut writer = reader
		.sync_adopted(base, |_, _| Ok::<_, ()>(()))
		.unwrap()
		.open_suffix_writer(base + 4, |_, _| Ok::<_, ()>(()))
		.unwrap();
	writer
		.begin_range(&issued_tail(4), |_| Ok::<_, ()>(()))
		.unwrap();
	writer.write_next(b"xy", |_, _| Ok::<_, ()>(())).unwrap();
	assert!(
		matches!(writer.write_next(b"z!", |_, _| Err::<(), _>("deadline")),
		Err(SuffixError::Admission { confirmed_end, cause: "deadline" }) if confirmed_end == base + 2)
	);
	assert!(
		writer
			.sync_range(|_, _| -> Result<(), ()> { panic!("poisoned writer reached sync") })
			.is_err()
	);
	assert!(writer.finish().is_err());
	let physical = fs::read(fixture.stage()).unwrap();
	assert_eq!(&physical[..PREFIX.len()], PREFIX);
	assert_eq!(&physical[PREFIX.len()..], b"xy");
	assert!(!fixture.target().exists());
}

#[test]
fn zero_tail_checks_admission_and_never_opens_a_writer() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let expected = selection(&inventory);
	let reader = lease.read_retained_prefix(&inventory, expected).unwrap();
	let end = PREFIX.len() as u64;
	let proof = reader.sync_adopted(end, |_, _| Ok::<_, ()>(())).unwrap();
	let checked = proof
		.zero_tail_readback(end, |actual, extent| {
			assert_eq!(actual, expected);
			assert_eq!(extent, end..end);
			Ok::<_, ()>(())
		})
		.unwrap();
	let mut bytes = [0; PREFIX.len()];
	checked.read_exact_at(0, &mut bytes).unwrap();
	checked.recheck_observation().unwrap();
	assert_eq!(&bytes, PREFIX);
	assert!(!fixture.target().exists());
}

#[test]
fn submitted_prefix_barrier_blocks_stage_reacquisition_for_the_same_lease() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let expected = inventory(&lease);
	let stage = selection(&expected);
	{
		let reader = lease.read_retained_prefix(&expected, stage).unwrap();
		let result = reader.sync_adopted_with(
			PREFIX.len() as u64,
			|_, _| Ok::<_, ()>(()),
			|_| Err(rustix::io::Errno::IO),
		);
		assert!(matches!(result, Err(SuffixError::Submitted { .. })));
	}
	assert!(matches!(
		lease.read_retained_prefix(&expected, stage),
		Err(StageError::JobBusy)
	));
	assert!(matches!(
		lease.reopen_stage_directory(&expected),
		Err(StageError::JobBusy)
	));
	expected.recheck().unwrap();
	assert_eq!(fs::read(fixture.stage()).unwrap(), PREFIX);
	drop(expected);
	drop(lease);

	// A different exclusive lease can inspect again. Replay/qualification must
	// independently authorize any later mutation.
	let lease = fixture.lease();
	let expected = inventory(&lease);
	assert!(
		lease
			.read_retained_prefix(&expected, selection(&expected))
			.is_ok()
	);
	assert!(!fixture.target().exists());
}
