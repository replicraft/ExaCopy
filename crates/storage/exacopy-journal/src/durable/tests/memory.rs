use std::cell::{Cell, RefCell};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use exacopy_endpoint::{JournalFileBarrier, JournalSegment};

use super::super::SyncedFrame;
use super::{DurableJournal, DurableJournalError};
use crate::frame::{ChainHead, FrameKind, FrameReadError, FrameWriteError, FrameWriter};

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
	extension_on_read: Cell<Option<&'static [u8]>>,
	bytes_read: Cell<usize>,
	refuse_seek_to: Cell<Option<u64>>,
}

struct MemorySegment<'test> {
	cursor: Cursor<Vec<u8>>,
	observations: &'test Observations,
	writable_bytes: usize,
}

impl Read for MemorySegment<'_> {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		if let Some(extension) = self.observations.extension_on_read.take() {
			self.cursor.get_mut().extend_from_slice(extension);
		}
		let count = self.cursor.read(buffer)?;
		self.observations
			.bytes_read
			.set(self.observations.bytes_read.get() + count);
		Ok(count)
	}
}

impl Seek for MemorySegment<'_> {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		if let SeekFrom::Start(offset) = position
			&& self.observations.refuse_seek_to.get() == Some(offset)
		{
			return Err(io::Error::other("injected cursor restore failure"));
		}
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

fn first_frame(observations: &Observations) -> (DurableJournal<MemorySegment<'_>>, SyncedFrame) {
	let segment = MemorySegment {
		cursor: Cursor::default(),
		observations,
		writable_bytes: FROZEN_CHAIN.len(),
	};
	let mut journal = DurableJournal::from_new_segment(segment).unwrap();
	let first = journal.append(FrameKind::JobPrepared, &[0xa0]).unwrap();
	(journal, first)
}

#[test]
fn current_confirmation_reads_the_frozen_chain_and_keeps_the_append_cursor() {
	let observations = Observations::default();
	let (mut journal, first) = first_frame(&observations);
	journal.confirm_current_frame(&first).unwrap();
	assert_eq!(observations.bytes_read.get(), FIRST_FRAME_BYTES);
	assert_eq!(
		*observations.written_bytes.borrow(),
		FROZEN_CHAIN[..FIRST_FRAME_BYTES]
	);
	assert_eq!(observations.barriers.borrow().len(), 1);

	let second = journal
		.append(FrameKind::PublishIntent, &[0xa1, 0, 1])
		.unwrap();
	observations.inspect_failure.set(true);
	assert!(matches!(
		journal.confirm_current_frame(&first),
		Err(DurableJournalError::StaleExpectedHead)
	));
	assert_eq!(observations.bytes_read.get(), FIRST_FRAME_BYTES);
	observations.inspect_failure.set(false);

	journal.confirm_current_frame(&second).unwrap();
	assert_eq!(
		observations.bytes_read.get(),
		FIRST_FRAME_BYTES + FROZEN_CHAIN.len()
	);
	assert_eq!(*observations.written_bytes.borrow(), FROZEN_CHAIN);
	assert_eq!(
		*observations.barriers.borrow(),
		[&FROZEN_CHAIN[..FIRST_FRAME_BYTES], FROZEN_CHAIN]
	);
}

#[test]
fn current_confirmation_retires_a_same_length_corrupt_or_rewritten_prefix() {
	let mut rewritten = FrameWriter::new(Vec::new(), ChainHead::start());
	rewritten.append(FrameKind::JobPrepared, &[0x80]).unwrap();
	let rewritten = rewritten.into_inner();
	assert_eq!(rewritten.len(), FIRST_FRAME_BYTES);

	let mut corrupt = FROZEN_CHAIN[..FIRST_FRAME_BYTES].to_vec();
	corrupt[FIRST_DIGEST_OFFSET] ^= 1;
	for (is_corrupt, bytes) in [(true, corrupt), (false, rewritten)] {
		let observations = Observations::default();
		let (mut journal, first) = first_frame(&observations);
		let segment = journal.writer.as_mut().unwrap().sink_mut();
		*segment.cursor.get_mut() = bytes;

		let result = journal.confirm_current_frame(&first);
		if is_corrupt {
			assert!(matches!(
				result,
				Err(DurableJournalError::ReadFrame(
					FrameReadError::Corrupt { .. }
				))
			));
		} else {
			assert!(matches!(result, Err(DurableJournalError::UnexpectedHead)));
		}
		assert_eq!(observations.bytes_read.get(), FIRST_FRAME_BYTES);
		assert_retired_without_writes(&mut journal, &first, &observations);
	}
}

#[test]
fn current_confirmation_reads_earlier_frames_even_when_terminal_bytes_are_unchanged() {
	let observations = Observations::default();
	let (mut journal, _) = first_frame(&observations);
	let second = journal
		.append(FrameKind::PublishIntent, &[0xa1, 0, 1])
		.unwrap();
	let bytes = journal.writer.as_mut().unwrap().sink_mut().cursor.get_mut();
	bytes[FIRST_DIGEST_OFFSET] ^= 1;
	assert_eq!(
		&bytes[FIRST_FRAME_BYTES..],
		&FROZEN_CHAIN[FIRST_FRAME_BYTES..]
	);

	assert!(matches!(
		journal.confirm_current_frame(&second),
		Err(DurableJournalError::ReadFrame(FrameReadError::Corrupt {
			offset: 0,
			..
		}))
	));
	assert_eq!(*observations.written_bytes.borrow(), FROZEN_CHAIN);
	assert_eq!(observations.barriers.borrow().len(), 2);
}

#[test]
fn current_confirmation_checks_extent_before_cursor_and_never_scans_a_longer_prefix() {
	for length in [FIRST_FRAME_BYTES - 1, FROZEN_CHAIN.len()] {
		let observations = Observations::default();
		let (mut journal, first) = first_frame(&observations);
		let cursor = &mut journal.writer.as_mut().unwrap().sink_mut().cursor;
		*cursor.get_mut() = FROZEN_CHAIN[..length].to_vec();
		cursor.set_position(0);

		assert!(matches!(
			journal.confirm_current_frame(&first),
			Err(DurableJournalError::UnexpectedLength { expected, actual })
				if expected == FIRST_FRAME_BYTES as u64 && actual == length as u64
		));
		assert_eq!(observations.bytes_read.get(), 0);
		assert_retired_without_writes(&mut journal, &first, &observations);
	}

	let observations = Observations::default();
	let (mut journal, first) = first_frame(&observations);
	journal
		.writer
		.as_mut()
		.unwrap()
		.sink_mut()
		.cursor
		.set_position(1);
	assert!(matches!(
		journal.confirm_current_frame(&first),
		Err(DurableJournalError::UnexpectedCursor { expected, actual: 1 })
			if expected == FIRST_FRAME_BYTES as u64
	));
	assert_eq!(observations.bytes_read.get(), 0);
	assert_retired_without_writes(&mut journal, &first, &observations);
}

#[test]
fn current_confirmation_checks_the_extra_eof_byte_and_retires_on_failed_restore() {
	let observations = Observations::default();
	let (mut journal, first) = first_frame(&observations);
	observations
		.extension_on_read
		.set(Some(&FROZEN_CHAIN[FIRST_FRAME_BYTES..]));
	assert!(matches!(
		journal.confirm_current_frame(&first),
		Err(DurableJournalError::ReadFrame(FrameReadError::TornTail {
			offset,
			bytes_read: 1,
		})) if offset == FIRST_FRAME_BYTES as u64
	));
	assert_eq!(observations.bytes_read.get(), FIRST_FRAME_BYTES + 1);
	assert_retired_without_writes(&mut journal, &first, &observations);

	let observations = Observations::default();
	let (mut journal, first) = first_frame(&observations);
	observations
		.refuse_seek_to
		.set(Some(FIRST_FRAME_BYTES as u64));
	assert!(matches!(
		journal.confirm_current_frame(&first),
		Err(DurableJournalError::Inspect(error))
			if error.to_string() == "injected cursor restore failure"
	));
	assert_eq!(observations.bytes_read.get(), FIRST_FRAME_BYTES);
	assert_retired_without_writes(&mut journal, &first, &observations);
}

fn assert_retired_without_writes(
	journal: &mut DurableJournal<MemorySegment<'_>>,
	expected: &SyncedFrame,
	observations: &Observations,
) {
	assert!(matches!(
		journal.confirm_current_frame(expected),
		Err(DurableJournalError::Retired)
	));
	assert!(matches!(
		journal.append(FrameKind::PublishIntent, &[0xa1, 0, 1]),
		Err(DurableJournalError::Retired)
	));
	assert_eq!(
		*observations.written_bytes.borrow(),
		FROZEN_CHAIN[..FIRST_FRAME_BYTES]
	);
	assert_eq!(
		*observations.barriers.borrow(),
		[&FROZEN_CHAIN[..FIRST_FRAME_BYTES]]
	);
}
