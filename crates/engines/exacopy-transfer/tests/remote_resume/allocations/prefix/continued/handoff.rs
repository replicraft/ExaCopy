use std::cell::Cell;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::task::{Context, Waker};

use exacopy_endpoint::ReadView;
use exacopy_transfer::remote_capture::{CapturedReadAt, SourceEpoch};
use exacopy_transfer::remote_resume::prefix::{
	RetainedPrefixIdentity, RetainedPrefixView, verify_held_retained_prefix,
};

use super::{
	Error, FRESH, FRESH_EPOCH, STREAM, Source, Stage, boundary_at, epoch, journal, ready, replay,
	source, stage,
};

#[path = "handoff/one_range.rs"]
mod one_range;
#[path = "handoff/prepublication.rs"]
mod prepublication;

struct Reader<'data> {
	stage: Stage<'data>,
	alive: &'data Cell<bool>,
	file_rebound: &'data Cell<bool>,
}

impl Drop for Reader<'_> {
	fn drop(&mut self) {
		self.alive.set(false);
	}
}

impl ReadView for Reader<'_> {
	type Error = &'static str;

	fn length(&self) -> u64 {
		self.stage.length()
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.stage.recheck_observation()
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		self.stage.read_exact_at(offset, bytes)
	}
}

impl RetainedPrefixView for Reader<'_> {
	fn identity(&self) -> RetainedPrefixIdentity<'_> {
		let mut identity = self.stage.identity();
		if self.file_rebound.get() {
			identity.file = identity.directory;
		}
		identity
	}
}

struct HeldSource<'data> {
	inner: Source<'data>,
	alive: &'data Cell<bool>,
	pause_suffix: bool,
	change_epoch: bool,
	false_eof: bool,
	finished: bool,
}

impl<'data> HeldSource<'data> {
	fn new(bytes: &'data [u8], alive: &'data Cell<bool>) -> Self {
		Self {
			inner: source(bytes),
			alive,
			pause_suffix: false,
			change_epoch: false,
			false_eof: false,
			finished: false,
		}
	}
}

impl CapturedReadAt for HeldSource<'_> {
	type Error = &'static str;

	fn epoch(&self) -> SourceEpoch {
		self.inner.epoch()
	}

	fn length(&self) -> u64 {
		self.inner.length()
	}

	fn max_window_bytes(&self) -> NonZeroUsize {
		self.inner.max_window_bytes()
	}

	async fn read_exact_at(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		assert!(self.alive.get());
		self.inner.read_exact_at(offset, bytes).await?;
		if offset >= 7 {
			if self.pause_suffix {
				std::future::pending::<()>().await;
			}
			if self.change_epoch {
				self.inner.epoch = epoch(FRESH_EPOCH + 1);
			}
		}
		Ok(())
	}

	async fn recheck(&mut self) -> Result<(), Self::Error> {
		assert!(self.alive.get());
		self.inner.recheck().await
	}

	async fn finish(&mut self) -> Result<(), Self::Error> {
		assert!(self.alive.get());
		assert!(!self.finished);
		self.finished = true;
		if self.false_eof {
			return Err("extra byte at EOF");
		}
		Ok(())
	}
}

#[test]
fn same_held_reader_and_fresh_hash_cover_signed_aggregate_checkpoints_tail_and_suffix() {
	let bytes = journal();
	let (after_first_suffix, _) = boundary_at(&bytes, 7);
	let scan = replay(&bytes[..after_first_suffix]);
	let history = scan.active_prefix_history().unwrap();
	let alive = Cell::new(true);
	let file_rebound = Cell::new(false);
	let mut remote = HeldSource::new(FRESH, &alive);
	let proof = ready(verify_held_retained_prefix(
		&history,
		&mut remote,
		epoch(FRESH_EPOCH),
		Reader {
			stage: stage(STREAM),
			alive: &alive,
			file_rebound: &file_rebound,
		},
		&mut [0; 4],
	))
	.unwrap();
	assert_eq!(proof.prefix().checkpoint_extent(), 5);
	assert_eq!(proof.prefix().extent(), 7);
	assert_eq!(proof.prefix().digest(), *blake3::hash(STREAM).as_bytes());
	let mut tail = proof.into_continuation();
	let mut scratch = [0; 8];
	assert_eq!(
		ready(tail.read_next(&mut scratch)).unwrap(),
		Some(b"H".as_slice())
	);
	scratch.fill(0xff);
	assert_eq!(ready(tail.read_next(&mut scratch)).unwrap(), None);
	let complete = ready(tail.finish()).unwrap();
	assert_eq!(complete.epoch(), epoch(FRESH_EPOCH));
	assert_eq!(complete.boundary(), scan.boundary());
	assert_eq!(complete.context(), history.context());
	assert_eq!(complete.scope(), history.scope());
	assert_eq!(complete.length(), 8);
	assert_eq!(
		complete.digest().as_slice(),
		super::hex("59a216db95aff0f8833f96f341fcb1f6594378096127c2b0fa9f3a849361d979"),
	);
	assert_eq!(remote.inner.reads, [(0, 2), (2, 2), (4, 1), (5, 2), (7, 1)]);
	assert!(remote.finished && alive.get());
	drop(complete);
	assert!(!alive.get());
}

#[test]
fn zero_tail_finishes_the_actual_source_and_detects_false_eof_and_rebound_stage() {
	let scan = replay(&journal());
	let history = scan.active_prefix_history().unwrap();
	for (false_eof, rebound) in [(false, false), (true, false), (false, true)] {
		let alive = Cell::new(true);
		let file_rebound = Cell::new(false);
		let mut remote = HeldSource::new(STREAM, &alive);
		remote.false_eof = false_eof;
		let proof = ready(verify_held_retained_prefix(
			&history,
			&mut remote,
			epoch(FRESH_EPOCH),
			Reader {
				stage: stage(STREAM),
				alive: &alive,
				file_rebound: &file_rebound,
			},
			&mut [0; 4],
		))
		.unwrap();
		file_rebound.set(rebound);
		match ready(proof.into_continuation().finish()) {
			Ok(complete) => {
				assert!(!false_eof && !rebound);
				assert_eq!(
					complete.digest().as_slice(),
					super::hex("5e521f668a0ebd5ba7cfdd6a924eb4e41b0dc842bbaedf656aa55533e9ee7ee7"),
				);
				assert!(alive.get());
			}
			Err(Error::SourceFinish("extra byte at EOF")) => assert!(false_eof),
			Err(Error::StageIdentity) => assert!(rebound),
			Err(error) => panic!("{error:?}"),
		}
		assert_eq!(remote.finished, !rebound);
		assert!(!alive.get());
	}
}

#[test]
fn attempted_suffix_failure_epoch_change_and_cancellation_stop_the_pass() {
	let scan = replay(&journal());
	let history = scan.active_prefix_history().unwrap();
	for mode in 0..3 {
		let alive = Cell::new(true);
		let file_rebound = Cell::new(false);
		let mut remote = HeldSource::new(FRESH, &alive);
		remote.inner.failed_read = (mode == 0).then_some(7);
		remote.change_epoch = mode == 1;
		remote.pause_suffix = mode == 2;
		let mut tail = ready(verify_held_retained_prefix(
			&history,
			&mut remote,
			epoch(FRESH_EPOCH),
			Reader {
				stage: stage(STREAM),
				alive: &alive,
				file_rebound: &file_rebound,
			},
			&mut [0; 4],
		))
		.unwrap()
		.into_continuation();
		let mut scratch = [0; 8];
		match mode {
			0 => assert!(matches!(
				ready(tail.read_next(&mut scratch)),
				Err(Error::SourceRead { offset: 7, .. })
			)),
			1 => assert!(matches!(
				ready(tail.read_next(&mut scratch)),
				Err(Error::Epoch)
			)),
			_ => {
				let mut read = pin!(tail.read_next(&mut scratch));
				assert!(
					read.as_mut()
						.poll(&mut Context::from_waker(Waker::noop()))
						.is_pending()
				);
			}
		}
		assert!(matches!(
			ready(tail.read_next(&mut scratch)),
			Err(Error::ContinuationStopped)
		));
		assert!(matches!(
			ready(tail.finish()),
			Err(Error::ContinuationStopped)
		));
		assert!(!remote.finished && !alive.get());
		assert_eq!(remote.inner.reads.last(), Some(&(7, 1)));
	}
}

#[test]
fn substituted_history_checkpoint_and_incomplete_suffix_are_refused() {
	let scan = replay(&journal());
	let history = scan.active_prefix_history().unwrap();
	let file_rebound = Cell::new(false);
	let alive = Cell::new(true);
	let mut remote = HeldSource::new(b"ABCDEFXH", &alive);
	let outcome = ready(verify_held_retained_prefix(
		&history,
		&mut remote,
		epoch(FRESH_EPOCH),
		Reader {
			stage: stage(b"ABCDEFX"),
			alive: &alive,
			file_rebound: &file_rebound,
		},
		&mut [0; 4],
	));
	assert!(matches!(
		outcome,
		Err(Error::CheckpointMismatch { offset: 5 })
	));

	alive.set(true);
	let mut different_native = stage(STREAM);
	different_native.name = b"wrong-stage";
	let mut remote = HeldSource::new(FRESH, &alive);
	let result = ready(verify_held_retained_prefix(
		&history,
		&mut remote,
		epoch(FRESH_EPOCH),
		Reader {
			stage: different_native,
			alive: &alive,
			file_rebound: &file_rebound,
		},
		&mut [0; 4],
	));
	assert!(matches!(result, Err(Error::StageIdentity)));
	drop(result);

	alive.set(true);
	let tail = ready(verify_held_retained_prefix(
		&history,
		&mut remote,
		epoch(FRESH_EPOCH),
		Reader {
			stage: stage(STREAM),
			alive: &alive,
			file_rebound: &file_rebound,
		},
		&mut [0; 4],
	))
	.unwrap()
	.into_continuation();
	assert!(matches!(
		ready(tail.finish()),
		Err(Error::IncompleteContinuation {
			offset: 7,
			length: 8
		})
	));
	assert!(!remote.finished && !alive.get());
}

#[test]
fn scoped_lending_keeps_the_exact_reader_through_terminal_source_read() {
	let scan = replay(&journal());
	let history = scan.active_prefix_history().unwrap();
	let alive = Cell::new(true);
	let file_rebound = Cell::new(false);
	let mut source = HeldSource::new(FRESH, &alive);
	let proof = ready(verify_held_retained_prefix(
		&history,
		&mut source,
		epoch(FRESH_EPOCH),
		Reader {
			stage: stage(STREAM),
			alive: &alive,
			file_rebound: &file_rebound,
		},
		&mut [0; 4],
	))
	.unwrap();
	let (source_observed, same_reader) = ready(proof.with_reader(async |mut live| {
		assert!(std::ptr::eq(live.reader().alive, &alive));
		assert_eq!(
			live.initial_prefix().unwrap().digest(),
			*blake3::hash(STREAM).as_bytes()
		);
		assert_eq!(
			live.read_next(&mut [0; 4]).await.unwrap(),
			Some(b"H".as_slice())
		);
		assert!(live.initial_prefix().is_none());
		live.finish().await.unwrap()
	}));
	assert!(source.finished && alive.get());
	assert!(std::ptr::eq(same_reader.reader().alive, &alive));
	assert_eq!(
		source_observed.digest().as_slice(),
		super::hex("59a216db95aff0f8833f96f341fcb1f6594378096127c2b0fa9f3a849361d979")
	);
	drop(same_reader);
	assert!(!alive.get());
}

#[test]
fn lent_cursor_reports_one_byte_displacement_and_stops_after_cancellation() {
	let scan = replay(&journal());
	let history = scan.active_prefix_history().unwrap();
	for cancelled in [false, true] {
		let alive = Cell::new(true);
		let file_rebound = Cell::new(false);
		let mut source = HeldSource::new(b"ABCDEFGHI", &alive);
		source.pause_suffix = cancelled;
		let checked = ready(verify_held_retained_prefix(
			&history,
			&mut source,
			epoch(FRESH_EPOCH),
			Reader {
				stage: stage(STREAM),
				alive: &alive,
				file_rebound: &file_rebound,
			},
			&mut [0; 4],
		))
		.unwrap();
		let (_, reader) = ready(checked.with_reader(async |mut live| {
			assert_eq!(live.next_offset(), Some(7));
			let mut byte = [0];
			if cancelled {
				{
					let mut read = pin!(live.read_next(&mut byte));
					assert!(
						read.as_mut()
							.poll(&mut Context::from_waker(Waker::noop()))
							.is_pending()
					);
				}
				assert_eq!(live.next_offset(), None);
			} else {
				assert_eq!(
					live.read_next(&mut byte).await.unwrap(),
					Some(b"H".as_slice())
				);
				assert_eq!(live.next_offset(), Some(8));
				assert_eq!(
					live.read_next(&mut byte).await.unwrap(),
					Some(b"I".as_slice())
				);
			}
		}));
		drop(reader);
		assert!(!alive.get());
	}
}
