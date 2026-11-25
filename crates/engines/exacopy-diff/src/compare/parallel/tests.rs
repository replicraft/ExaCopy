use std::io::{self, ErrorKind};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::Duration;

use exacopy_endpoint::{MAX_FILE_LENGTH, ReadView};

use super::partition;
use crate::{
	CompareError, Difference, LiveComparison, MAX_SCRATCH_BYTES, MAX_WORKERS, Side,
	compare_parallel,
};

const TIMEOUT: Duration = Duration::from_secs(5);

struct View<'a> {
	bytes: &'a [u8],
	reads: Mutex<Vec<(u64, usize)>>,
	checks: AtomicUsize,
	fail_check: Option<usize>,
	before_read: Option<&'a (dyn Fn(u64) -> io::Result<()> + Sync)>,
}

impl<'a> View<'a> {
	fn new(bytes: &'a [u8]) -> Self {
		Self {
			bytes,
			reads: Mutex::default(),
			checks: AtomicUsize::default(),
			fail_check: None,
			before_read: None,
		}
	}
}

impl ReadView for View<'_> {
	type Error = io::Error;

	fn length(&self) -> u64 {
		u64::try_from(self.bytes.len()).expect("fixture length fits")
	}

	fn recheck_observation(&self) -> io::Result<()> {
		let check = self.checks.fetch_add(1, Ordering::Relaxed);
		if self.fail_check == Some(check) {
			return Err(io::Error::other("fixture changed"));
		}
		Ok(())
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
		self.reads
			.lock()
			.expect("record read")
			.push((offset, buffer.len()));
		if let Some(before_read) = self.before_read {
			before_read(offset)?;
		}
		let start = usize::try_from(offset).expect("fixture offset fits");
		buffer.copy_from_slice(&self.bytes[start..start + buffer.len()]);
		Ok(())
	}
}

fn ceiling(workers: usize) -> NonZeroUsize {
	NonZeroUsize::new(workers).expect("nonzero test worker count")
}

#[test]
fn partitions_cover_every_byte_without_overflow_or_overlap() {
	let small_lengths = 0..=127;
	let high_lengths = (MAX_FILE_LENGTH - 127)..=MAX_FILE_LENGTH;
	let worker_cap = u64::try_from(MAX_WORKERS).expect("worker cap fits");
	for length in small_lengths.chain(high_lengths) {
		for workers in 0..=worker_cap {
			assert_eq!(partition(length, workers, workers), None);
			if workers > length || workers == 0 {
				assert_eq!(partition(length, workers, 0), None);
				continue;
			}
			let mut next = 0;
			let mut min_width = length;
			let mut max_width = 0;
			for index in 0..workers {
				let range = partition(length, workers, index).expect("partition exists");
				assert_eq!(range.start, next, "{length}, {workers}, {index}");
				assert!(range.end > range.start && range.end <= length);
				let width = range.end - range.start;
				min_width = min_width.min(width);
				max_width = max_width.max(width);
				next = range.end;
			}
			assert_eq!(next, length);
			assert!(max_width - min_width <= 1);
		}
	}
}

#[test]
fn returns_first_mismatch_for_every_pair_of_positions_and_odd_buffer_sizes() {
	let left_bytes = b"\0a\0b\xFFc\0d\0";
	for scratch_len in [2, 3, 5, 9, 17, 33] {
		for workers in [1, 2, 3, MAX_WORKERS] {
			for first in 0..left_bytes.len() {
				for second in first..left_bytes.len() {
					let mut right_bytes = *left_bytes;
					right_bytes[first] ^= 1;
					right_bytes[second] ^= 2;
					assert_ne!(left_bytes[first], right_bytes[first]);
					let left = View::new(left_bytes);
					let right = View::new(&right_bytes);
					let expected = u64::try_from(first).expect("fixture offset fits");
					assert_eq!(
						compare_parallel(
							&left,
							&right,
							&mut vec![0; scratch_len],
							ceiling(workers)
						)
						.expect("compare fixture"),
						LiveComparison::Different(Difference::FirstByte { offset: expected }),
						"{scratch_len} scratch bytes, {workers} workers, first {first}, second {second}"
					);
				}
			}
		}
	}
}

#[test]
fn reads_every_offset_once_per_side_in_its_independent_scratch_window() {
	let bytes = b"abcdefghijklmnopqrstuvwxyz";
	let length = u64::try_from(bytes.len()).expect("fixture length fits");
	let left = View::new(bytes);
	let right = View::new(bytes);
	assert_eq!(
		compare_parallel(&left, &right, &mut [0; 17], ceiling(3)).expect("compare fixture"),
		LiveComparison::Equal { length }
	);
	for view in [&left, &right] {
		let mut reads = view.reads.lock().expect("read trace");
		reads.sort_unstable();
		assert_eq!(
			*reads,
			[
				(0, 2),
				(2, 2),
				(4, 2),
				(6, 2),
				(8, 1),
				(9, 2),
				(11, 2),
				(13, 2),
				(15, 2),
				(17, 1),
				(18, 2),
				(20, 2),
				(22, 2),
				(24, 2)
			]
		);
		assert_eq!(view.checks.load(Ordering::Relaxed), 2);
	}
}

#[test]
fn validates_before_reading_and_does_not_start_workers_for_length_only_results() {
	let empty = View::new(b"");
	let nonempty = View::new(b"ab");
	let error =
		compare_parallel(&nonempty, &nonempty, &mut [0; 4], ceiling(MAX_WORKERS + 1)).unwrap_err();
	assert!(
		matches!(error, CompareError::TooManyWorkers { workers } if workers == MAX_WORKERS + 1)
	);
	assert!(matches!(
		compare_parallel(&nonempty, &nonempty, &mut [0], ceiling(2)),
		Err(CompareError::InsufficientScratch)
	));
	assert!(matches!(
		compare_parallel(
			&nonempty,
			&nonempty,
			&mut vec![0; MAX_SCRATCH_BYTES + 1],
			ceiling(2)
		),
		Err(CompareError::ScratchTooLarge { .. })
	));
	assert_eq!(nonempty.checks.load(Ordering::Relaxed), 0);

	assert_eq!(
		compare_parallel(&empty, &empty, &mut [], ceiling(2)).expect("empty equality"),
		LiveComparison::Equal { length: 0 }
	);
	assert_eq!(
		compare_parallel(&empty, &nonempty, &mut [], ceiling(2)).expect("length difference"),
		LiveComparison::Different(Difference::Length { left: 0, right: 2 })
	);
	for view in [&nonempty, &empty] {
		assert!(view.reads.lock().expect("read trace").is_empty());
	}
}

#[test]
fn ordered_results_require_all_earlier_reads_but_allow_later_speculation() {
	for earlier_error in [false, true] {
		let (later_started, await_later) = mpsc::channel();
		let await_later = Mutex::new(await_later);
		let inject = |offset| {
			if offset == 0 {
				await_later
					.lock()
					.expect("lock event")
					.recv_timeout(TIMEOUT)
					.expect("later partition must start concurrently");
				if !earlier_error {
					return Ok(());
				}
			} else {
				later_started.send(()).expect("notify first partition");
			}
			Err(ErrorKind::UnexpectedEof.into())
		};
		let left = View {
			before_read: Some(&inject),
			..View::new(b"aaaaaaaa")
		};
		let right = View::new(b"baaaaaaa");
		let result = compare_parallel(&left, &right, &mut [0; 16], ceiling(2));
		if earlier_error {
			assert!(matches!(
				result,
				Err(CompareError::Read { side: Side::Left, offset: 0, source })
					if source.kind() == ErrorKind::UnexpectedEof
			));
		} else {
			assert_eq!(
				result.expect("earlier mismatch has been read"),
				LiveComparison::Different(Difference::FirstByte { offset: 0 })
			);
		}
	}
}

#[test]
fn waits_for_started_workers_before_the_final_observation_check() {
	let (later_started, await_later) = mpsc::channel();
	let (first_read, await_first) = mpsc::channel();
	let (release_later, later_release) = mpsc::channel();
	let await_later = Mutex::new(await_later);
	let later_release = Mutex::new(later_release);
	let first = |offset| {
		match offset {
			0 => await_later
				.lock()
				.expect("lock event")
				.recv_timeout(TIMEOUT)
				.expect("observe outstanding higher range"),
			4 => {
				later_started.send(()).expect("notify first partition");
				later_release
					.lock()
					.expect("lock release")
					.recv_timeout(TIMEOUT)
					.expect("release outstanding read");
			}
			_ => panic!("unexpected partition start {offset}"),
		}
		Ok(())
	};
	let second = |offset| {
		if offset == 0 {
			first_read
				.send(())
				.expect("notify controller of first mismatch");
		}
		Ok(())
	};
	let left = View {
		before_read: Some(&first),
		..View::new(b"aaaaaaaa")
	};
	let right = View {
		before_read: Some(&second),
		fail_check: Some(1),
		..View::new(b"baaaaaaa")
	};

	thread::scope(|scope| {
		let comparison = scope.spawn(|| compare_parallel(&left, &right, &mut [0; 16], ceiling(2)));
		await_first
			.recv_timeout(TIMEOUT)
			.expect("first mismatch had an outstanding read");
		assert_eq!(left.checks.load(Ordering::Relaxed), 1);
		assert_eq!(right.checks.load(Ordering::Relaxed), 1);
		assert!(!comparison.is_finished());
		release_later.send(()).expect("release outstanding read");
		assert!(matches!(
			comparison.join().expect("coordinator completed"),
			Err(CompareError::Observation {
				side: Side::Right,
				..
			})
		));
	});
}

#[test]
fn a_started_worker_panic_is_inconclusive() {
	let (later_started, await_later) = mpsc::channel();
	let await_later = Mutex::new(await_later);
	let inject = |offset| {
		if offset == 0 {
			await_later
				.lock()
				.expect("lock event")
				.recv_timeout(TIMEOUT)
				.expect("later worker started");
		} else {
			later_started.send(()).expect("notify first partition");
			panic!("fixture panic at offset {offset}");
		}
		Ok(())
	};
	let left = View {
		before_read: Some(&inject),
		..View::new(b"aaaa")
	};
	let right = View::new(b"baaa");
	assert!(matches!(
		compare_parallel(&left, &right, &mut [0; 8], ceiling(2)),
		Err(CompareError::WorkerPanicked { offset: 2 })
	));
}
