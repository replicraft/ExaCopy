use std::cell::{Cell, RefCell};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use exacopy_endpoint::{JournalFileBarrier, JournalSegment};

use super::{DurableJournal, DurableJournalError};
use crate::frame::{ChainHead, FrameKind, FrameWriteError};

const FROZEN_CHAIN: &[u8] = include_bytes!("../../../fuzz/corpus/journal_frame/two-valid-frames");
const FIRST_FRAME_BYTES: usize = 93;
const FIRST_DIGEST_OFFSET: usize = 61;

#[derive(Default)]
struct Observations {
	barriers: RefCell<Vec<Vec<u8>>>,
	written_bytes: RefCell<Vec<u8>>,
	inspect_failure: Cell<bool>,
	expire_on_inspection: Cell<bool>,
	clock: Cell<u64>,
	require_guard: Cell<bool>,
	guard_held: Cell<bool>,
}

struct MemorySegment<'test> {
	cursor: Cursor<Vec<u8>>,
	observations: &'test Observations,
	writable_bytes: usize,
}

impl Read for MemorySegment<'_> {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		self.cursor.read(buffer)
	}
}

impl Seek for MemorySegment<'_> {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		self.cursor.seek(position)
	}
}

impl Write for MemorySegment<'_> {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		if self.observations.require_guard.get() {
			assert!(self.observations.guard_held.get());
			// An admitted frame may finish even if its deadline passes during writes.
			self.observations.clock.set(2);
		}
		if self.writable_bytes == 0 {
			return Err(io::Error::other("injected write failure"));
		}
		let bytes = &bytes[..bytes.len().min(self.writable_bytes)];
		let written = self.cursor.write(bytes)?;
		self.observations
			.written_bytes
			.borrow_mut()
			.extend_from_slice(&bytes[..written]);
		self.writable_bytes -= written;
		Ok(written)
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

/// Records which complete bytes reached each simulated full file barrier.
impl JournalSegment for MemorySegment<'_> {
	const BARRIER: JournalFileBarrier = JournalFileBarrier::SyncAll;

	fn regular_length(&self) -> io::Result<Option<u64>> {
		if self.observations.expire_on_inspection.get() {
			assert!(!self.observations.guard_held.get());
			self.observations.clock.set(2);
		}
		if self.observations.inspect_failure.get() {
			return Err(io::Error::other("injected extent inspection failure"));
		}
		Ok(Some(self.cursor.get_ref().len().try_into().unwrap()))
	}

	fn sync(&self) -> io::Result<()> {
		if self.observations.require_guard.get() {
			assert!(self.observations.guard_held.get());
			assert_eq!(self.observations.clock.get(), 2);
		}
		self.observations
			.barriers
			.borrow_mut()
			.push(self.cursor.get_ref().clone());
		Ok(())
	}
}

#[test]
fn a_generic_segment_matches_the_frozen_frame_chain_through_resume() {
	let observations = Observations::default();
	let initial = MemorySegment {
		cursor: Cursor::default(),
		observations: &observations,
		writable_bytes: FROZEN_CHAIN.len(),
	};
	let mut journal = DurableJournal::from_new_segment(initial).unwrap();
	let first = journal.append(FrameKind::JobPrepared, &[0xa0]).unwrap();
	let digest = FROZEN_CHAIN[FIRST_DIGEST_OFFSET..FIRST_FRAME_BYTES]
		.try_into()
		.unwrap();
	let first_head = ChainHead::after(1, digest).unwrap();
	assert_eq!(first.head(), first_head);
	assert_eq!(first.barrier(), JournalFileBarrier::SyncAll);
	let retained = observations.barriers.borrow()[0].clone();
	assert_eq!(retained, FROZEN_CHAIN[..FIRST_FRAME_BYTES]);
	drop(journal);

	let old_length = retained.len().try_into().unwrap();
	let recovered = MemorySegment {
		cursor: Cursor::new(retained),
		observations: &observations,
		writable_bytes: FROZEN_CHAIN.len() - FIRST_FRAME_BYTES,
	};
	let mut journal = DurableJournal::resume_first_segment(recovered, first_head, old_length)
		.expect("admit the exact complete prefix");
	let (frame, synced) = journal
		.append_frame(FrameKind::PublishIntent, vec![0xa1, 0, 1])
		.unwrap();
	assert_eq!(frame.previous_digest(), digest);
	assert_eq!(frame.head(), synced.head());
	assert_eq!(
		*observations.barriers.borrow(),
		[
			&FROZEN_CHAIN[..FIRST_FRAME_BYTES],
			&FROZEN_CHAIN[..FIRST_FRAME_BYTES],
			FROZEN_CHAIN,
		]
	);
	assert_eq!(*observations.written_bytes.borrow(), FROZEN_CHAIN);
}

#[test]
fn a_partial_write_retires_the_writer_without_barriering_partial_bytes() {
	const PARTIAL_BYTES: usize = 10;
	let observations = Observations::default();
	let segment = MemorySegment {
		cursor: Cursor::default(),
		observations: &observations,
		writable_bytes: PARTIAL_BYTES,
	};
	let mut journal = DurableJournal::from_new_segment(segment).unwrap();
	assert!(matches!(
		journal.append(FrameKind::JobPrepared, &[0xa0]),
		Err(DurableJournalError::Frame(FrameWriteError::Io(_)))
	));
	assert!(matches!(
		journal.append(FrameKind::JobPrepared, &[0xa0]),
		Err(DurableJournalError::Retired)
	));
	assert_eq!(
		*observations.written_bytes.borrow(),
		FROZEN_CHAIN[..PARTIAL_BYTES]
	);
	assert!(observations.barriers.borrow().is_empty());
}

#[test]
fn an_inspection_failure_retires_the_writer_without_writing() {
	let observations = Observations::default();
	let segment = MemorySegment {
		cursor: Cursor::default(),
		observations: &observations,
		writable_bytes: FROZEN_CHAIN.len(),
	};
	let mut journal = DurableJournal::from_new_segment(segment).unwrap();
	observations.inspect_failure.set(true);
	assert!(matches!(
		journal.append(FrameKind::JobPrepared, &[0xa0]),
		Err(DurableJournalError::Inspect(_))
	));
	observations.inspect_failure.set(false);
	assert!(matches!(
		journal.append(FrameKind::JobPrepared, &[0xa0]),
		Err(DurableJournalError::Retired)
	));
	assert!(observations.written_bytes.borrow().is_empty());
	assert!(observations.barriers.borrow().is_empty());
}

#[test]
fn deadline_crossed_by_physical_preflight_submits_no_frame_or_barrier() {
	let observations = Observations::default();
	let segment = MemorySegment {
		cursor: Cursor::default(),
		observations: &observations,
		writable_bytes: FROZEN_CHAIN.len(),
	};
	let mut journal = DurableJournal::from_new_segment(segment).unwrap();
	observations.clock.set(1);
	observations.expire_on_inspection.set(true);
	let result = journal.append_frame_admitted(FrameKind::JobPrepared, vec![0xa0], || {
		assert_eq!(observations.clock.get(), 2);
		Err::<(), _>(io::Error::other("deadline expired during preflight"))
	});
	assert!(matches!(result, Err(DurableJournalError::Admission(_))));
	assert!(observations.written_bytes.borrow().is_empty());
	assert!(observations.barriers.borrow().is_empty());
	observations.expire_on_inspection.set(false);
	let first = journal.append(FrameKind::JobPrepared, &[0xa0]).unwrap();
	assert_eq!(first.head().sequence(), 1);
	assert_eq!(
		*observations.written_bytes.borrow(),
		FROZEN_CHAIN[..FIRST_FRAME_BYTES]
	);
}

struct ObservedGuard<'test>(&'test Cell<bool>);

impl Drop for ObservedGuard<'_> {
	fn drop(&mut self) {
		self.0.set(false);
	}
}

#[test]
fn one_admitted_frame_finishes_its_write_and_barrier_before_releasing_the_guard() {
	let observations = Observations::default();
	let segment = MemorySegment {
		cursor: Cursor::default(),
		observations: &observations,
		writable_bytes: FROZEN_CHAIN.len(),
	};
	let mut journal = DurableJournal::from_new_segment(segment).unwrap();
	observations.clock.set(1);
	observations.require_guard.set(true);
	let (frame, synced) = journal
		.append_frame_admitted(FrameKind::JobPrepared, vec![0xa0], || {
			assert_eq!(observations.clock.get(), 1);
			assert!(!observations.guard_held.replace(true));
			Ok(ObservedGuard(&observations.guard_held))
		})
		.unwrap();
	assert_eq!(frame.head(), synced.head());
	assert!(!observations.guard_held.get());
	assert_eq!(
		*observations.barriers.borrow(),
		[&FROZEN_CHAIN[..FIRST_FRAME_BYTES]]
	);
}

#[test]
fn resumed_segment_barrier_refuses_after_physical_preflight() {
	let observations = Observations::default();
	let segment = MemorySegment {
		cursor: Cursor::default(),
		observations: &observations,
		writable_bytes: FROZEN_CHAIN.len(),
	};
	let mut journal = DurableJournal::from_new_segment(segment).unwrap();
	let head = journal
		.append(FrameKind::JobPrepared, &[0xa0])
		.unwrap()
		.head();
	drop(journal);

	observations.clock.set(1);
	observations.expire_on_inspection.set(true);
	let recovered = MemorySegment {
		cursor: Cursor::new(FROZEN_CHAIN[..FIRST_FRAME_BYTES].to_vec()),
		observations: &observations,
		writable_bytes: FROZEN_CHAIN.len() - FIRST_FRAME_BYTES,
	};
	let result = DurableJournal::resume_first_segment_admitted(
		recovered,
		head,
		FIRST_FRAME_BYTES.try_into().unwrap(),
		|| {
			assert_eq!(observations.clock.get(), 2);
			Err::<(), _>(io::Error::other(
				"expired during the resumed segment's probes",
			))
		},
	);
	assert!(matches!(result, Err(DurableJournalError::Admission(_))));
	assert_eq!(observations.barriers.borrow().len(), 1);
	assert_eq!(
		*observations.written_bytes.borrow(),
		FROZEN_CHAIN[..FIRST_FRAME_BYTES]
	);
}
