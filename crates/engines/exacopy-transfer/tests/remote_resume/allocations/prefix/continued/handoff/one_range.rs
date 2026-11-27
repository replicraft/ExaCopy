use std::cell::Cell;

use super::{
	Error, FRESH_EPOCH, HeldSource, Reader, STREAM, boundary_at, epoch, journal, ready, replay,
	stage, verify_held_retained_prefix,
};

const FRESH_SOURCE: &[u8] = b"ABCDEFGHI";
const RETAINED_END: u64 = 7;
const SOURCE_END: u64 = 9;
const PREFIX_READS: [(u64, usize); 4] = [(0, 2), (2, 2), (4, 1), (5, 2)];
const SUFFIX_READS: [(u64, usize); 2] = [(RETAINED_END, 1), (RETAINED_END + 1, 1)];

#[test]
fn one_positive_range_consumes_only_fresh_suffix_windows_after_verified_reuse() {
	let bytes = journal();
	let (cut, _) = boundary_at(&bytes, 7);
	let scan = replay(&bytes[..cut]);
	let history = scan
		.active_prefix_history()
		.expect("continued checkpoint history");
	let alive = Cell::new(true);
	let file_rebound = Cell::new(false);
	let mut source = HeldSource::new(FRESH_SOURCE, &alive);
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
	.expect("current bytes match the continued aggregate, checkpoint and retained tail");

	let (observed, reader) = ready(proof.with_reader(async |mut live| {
		let prefix = live.initial_prefix().expect("freshly verified prefix");
		assert_eq!(prefix.checkpoint_extent(), 5);
		assert_eq!(prefix.extent(), RETAINED_END);
		assert_eq!(*live.reader().stage.reads.borrow(), PREFIX_READS);

		let mut window = [0];
		for (offset, expected) in [(RETAINED_END, b"H"), (RETAINED_END + 1, b"I")] {
			assert_eq!(live.next_offset(), Some(offset));
			let bytes = live
				.read_next(&mut window)
				.await
				.expect("bounded suffix read");
			assert_eq!(
				bytes,
				Some(expected.as_slice()),
				"suffix window at {offset}"
			);
			assert!(live.initial_prefix().is_none());
			window.fill(0xff);
		}
		assert_eq!(live.next_offset(), Some(SOURCE_END));
		assert!(
			live.read_next(&mut window)
				.await
				.expect("observed extent")
				.is_none()
		);
		assert!(!live.source().finished);
		live.finish().await.expect("terminal source check")
	}));

	assert_eq!(observed.epoch(), epoch(FRESH_EPOCH));
	assert_eq!(observed.length(), SOURCE_END);
	assert_eq!(observed.digest(), *blake3::hash(FRESH_SOURCE).as_bytes());
	assert_eq!(
		source.inner.reads,
		[PREFIX_READS.as_slice(), &SUFFIX_READS].concat()
	);
	assert_eq!(*reader.reader().stage.reads.borrow(), PREFIX_READS);
	assert!(source.finished && alive.get());
	drop(reader);
	assert!(!alive.get());
}

#[test]
fn equal_extent_cannot_create_a_positive_range_handoff_after_reuse_mismatch() {
	let bytes = journal();
	let (cut, _) = boundary_at(&bytes, 7);
	let scan = replay(&bytes[..cut]);
	let history = scan
		.active_prefix_history()
		.expect("continued checkpoint history");
	let changed_checkpoint_source = b"ABCDXFGHI";
	let changed_checkpoint_stage = b"ABCDXFG";
	let changed_retained_tail_source = b"ABCDEFXHI";
	let cases = [
		(
			changed_checkpoint_source.as_slice(),
			STREAM,
			Error::<&str, &str>::SourceMismatch { offset: 4 },
			&PREFIX_READS[..3],
		),
		(
			changed_checkpoint_source.as_slice(),
			changed_checkpoint_stage.as_slice(),
			Error::CheckpointMismatch { offset: 4 },
			&PREFIX_READS[..3],
		),
		(
			changed_retained_tail_source.as_slice(),
			STREAM,
			Error::TailMismatch { offset: 5 },
			PREFIX_READS.as_slice(),
		),
	];

	for (source_bytes, retained_bytes, expected, reads) in cases {
		let alive = Cell::new(true);
		let file_rebound = Cell::new(false);
		let mut source = HeldSource::new(source_bytes, &alive);
		let outcome = ready(verify_held_retained_prefix(
			&history,
			&mut source,
			epoch(FRESH_EPOCH),
			Reader {
				stage: stage(retained_bytes),
				alive: &alive,
				file_rebound: &file_rebound,
			},
			&mut [0; 4],
		));
		let Err(error) = outcome else {
			panic!("corrupt retained coverage handed off a suffix cursor");
		};
		match (expected, error) {
			(Error::SourceMismatch { offset: expected }, Error::SourceMismatch { offset })
			| (
				Error::CheckpointMismatch { offset: expected },
				Error::CheckpointMismatch { offset },
			)
			| (Error::TailMismatch { offset: expected }, Error::TailMismatch { offset }) => {
				assert_eq!(offset, expected);
			}
			(expected, actual) => panic!("expected {expected:?}, got {actual:?}"),
		}
		assert_eq!(source.inner.reads.as_slice(), reads);
		assert!(!source.finished && !alive.get());
	}
}

#[test]
fn interrupted_second_window_of_one_positive_range_cannot_return_terminal_evidence() {
	let bytes = journal();
	let (cut, _) = boundary_at(&bytes, 7);
	let scan = replay(&bytes[..cut]);
	let history = scan
		.active_prefix_history()
		.expect("continued checkpoint history");
	let alive = Cell::new(true);
	let file_rebound = Cell::new(false);
	let mut source = HeldSource::new(FRESH_SOURCE, &alive);
	let failing_offset = RETAINED_END + 1;
	source.inner.failed_read = Some(failing_offset);
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
	.expect("full retained comparison should precede the injected suffix failure");

	let (outcome, reader) = ready(proof.with_reader(async |mut live| {
		let mut window = [0];
		assert_eq!(
			live.read_next(&mut window)
				.await
				.expect("first suffix window"),
			Some(b"H".as_slice()),
		);
		assert_eq!(live.next_offset(), Some(failing_offset));
		assert!(matches!(
			live.read_next(&mut window).await,
			Err(Error::SourceRead { offset, cause: "interrupted window" })
				if offset == failing_offset
		));
		assert_eq!(live.next_offset(), None);
		assert!(live.initial_prefix().is_none());
		assert!(matches!(
			live.read_next(&mut window).await,
			Err(Error::ContinuationStopped)
		));
		live.finish().await
	}));
	assert!(matches!(outcome, Err(Error::ContinuationStopped)));
	assert_eq!(
		source.inner.reads,
		[PREFIX_READS.as_slice(), &SUFFIX_READS].concat()
	);
	assert!(!source.finished && alive.get());
	assert_eq!(*reader.reader().stage.reads.borrow(), PREFIX_READS);
	drop(reader);
	assert!(!alive.get());
}
