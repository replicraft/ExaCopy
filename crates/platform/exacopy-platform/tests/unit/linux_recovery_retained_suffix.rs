use std::cell::Cell;
use std::fs;
use std::io::ErrorKind;

use super::{Fixture, PREFIX, inventory, issued_tail, selection};
use crate::linux::{StageError, SuffixEffect, SuffixError};

#[test]
fn prefix_extent_and_admission_refusal_never_submit_the_barrier() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let expected = selection(&inventory);
	let reader = lease.read_retained_prefix(&inventory, expected).unwrap();
	let end = PREFIX.len() as u64;

	assert!(matches!(
		reader.sync_adopted_with(
			end + 1,
			|_, _| -> Result<(), ErrorKind> { panic!("wrong extent reached admission") },
			|_| panic!("wrong extent reached the file barrier"),
		),
		Err(SuffixError::Observation(StageError::IdentityChanged))
	));
	assert!(matches!(
		reader.sync_adopted_with(
			end,
			|actual, effect| {
				assert_eq!(actual, expected);
				assert_eq!(effect, SuffixEffect::PrefixBarrier { end });
				Err::<(), _>(ErrorKind::PermissionDenied)
			},
			|_| panic!("refused admission reached the file barrier"),
		),
		Err(SuffixError::Admission {
			confirmed_end,
			cause: ErrorKind::PermissionDenied,
		}) if confirmed_end == end
	));
	assert!(matches!(
		reader.sync_adopted(end, |_, _| -> Result<(), ErrorKind> {
			panic!("the original reader accepted a second barrier attempt")
		}),
		Err(SuffixError::Observation(StageError::IdentityChanged))
	));
	drop(reader);
	assert!(lease.read_retained_prefix(&inventory, expected).is_ok());
	assert_eq!(fs::read(fixture.stage()).unwrap(), PREFIX);
	assert!(!fixture.target().exists());
}

#[test]
fn zero_tail_refuses_target_that_appears_at_continuation_admission() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let expected = selection(&inventory);
	let reader = lease.read_retained_prefix(&inventory, expected).unwrap();
	let end = PREFIX.len() as u64;
	let synced = reader.sync_adopted(end, |_, _| Ok::<_, ()>(())).unwrap();
	assert_eq!(synced.end(), end);
	assert!(synced.matches_reader(&reader));

	assert!(matches!(
		synced.zero_tail_readback(end, |actual, extent| {
			assert_eq!(actual, expected);
			assert_eq!(extent, end..end);
			fs::write(fixture.target(), b"incumbent").unwrap();
			Ok::<_, ()>(())
		}),
		Err(SuffixError::Observation(StageError::IdentityChanged))
	));
	assert_eq!(fs::read(fixture.target()).unwrap(), b"incumbent");
	assert_eq!(fs::read(fixture.stage()).unwrap(), PREFIX);
}

#[test]
fn stale_checkpoint_refuses_to_release_the_writer_and_preserves_both_files() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let reader = lease
		.read_retained_prefix(&inventory, selection(&inventory))
		.unwrap();
	let base = PREFIX.len() as u64;
	let end = base + 4;
	let mut writer = reader
		.sync_adopted(base, |_, _| Ok::<_, ()>(()))
		.unwrap()
		.open_suffix_writer(end, |_, _| Ok::<_, ()>(()))
		.unwrap();
	assert!(writer.matches_reader(&reader));
	writer
		.begin_range(&issued_tail(4), |_| Ok::<_, ()>(()))
		.unwrap();
	writer.write_next(b"tail", |_, _| Ok::<_, ()>(())).unwrap();
	assert_eq!(writer.sync_range(|_, _| Ok::<_, ()>(())).unwrap(), end);
	let proof = writer.checkpoint_proof().unwrap();

	fs::write(fixture.target(), b"incumbent").unwrap();
	assert!(matches!(
		proof.check_for(&reader),
		Err(StageError::IdentityChanged)
	));
	assert!(matches!(
		writer.checkpoint_proof(),
		Err(StageError::IdentityChanged)
	));
	assert!(matches!(
		writer.confirm_checkpoint(|_| -> Result<(), ()> {
			panic!("stale checkpoint reached admission")
		}),
		Err(SuffixError::Observation(StageError::IdentityChanged))
	));
	assert!(matches!(writer.finish(), Err(StageError::Unflushed)));
	assert_eq!(fs::read(fixture.target()).unwrap(), b"incumbent");
	assert_eq!(
		fs::read(fixture.stage()).unwrap(),
		[PREFIX, b"tail"].concat()
	);
}

#[test]
fn interrupted_write_rechecks_the_same_cursor_and_zero_progress_stops_it() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let reader = lease
		.read_retained_prefix(&inventory, selection(&inventory))
		.unwrap();
	let base = PREFIX.len() as u64;
	let mut writer = reader
		.sync_adopted(base, |_, _| Ok::<_, ()>(()))
		.unwrap()
		.open_suffix_writer(base + 4, |_, _| Ok::<_, ()>(()))
		.unwrap();
	writer
		.begin_range(&issued_tail(4), |_| Ok::<_, ()>(()))
		.unwrap();

	let gates = Cell::new(0);
	let mut writes = 0;
	assert!(matches!(
		writer.write_next_with(
			b"tail",
			|| Ok::<_, ()>(()),
			|_, effect| {
				assert_eq!(effect, SuffixEffect::Write { offset: base, length: 4 });
				gates.set(gates.get() + 1);
				Ok(())
			},
			|_, bytes, offset| {
				assert_eq!(bytes, b"tail");
				assert_eq!(offset, base);
				writes += 1;
				assert_eq!(gates.get(), writes);
				match writes {
					1 => Err(ErrorKind::Interrupted.into()),
					2 => Ok(0),
					_ => panic!("unexpected positional write after zero progress"),
				}
			},
		),
		Err(SuffixError::Submitted {
			confirmed_end,
			cause: StageError::System(cause),
		}) if confirmed_end == base && cause.kind() == ErrorKind::WriteZero
	));
	assert_eq!(writes, 2);
	assert!(matches!(
		writer.write_next(b"tail", |_, _| -> Result<(), ()> {
			panic!("the stopped writer reached admission")
		}),
		Err(SuffixError::Observation(StageError::PriorBarrierFailure))
	));
	assert!(matches!(writer.finish(), Err(StageError::Unflushed)));
	assert_eq!(fs::read(fixture.stage()).unwrap(), PREFIX);
	assert!(!fixture.target().exists());
}
