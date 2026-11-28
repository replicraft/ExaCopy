use std::cell::Cell;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use exacopy_endpoint::{JournalFileBarrier, JournalSegment};

use super::super::super::{DurableJournal, SyncedFrame};
use crate::frame::FrameKind;

#[derive(Default)]
pub(super) struct State {
	pub(super) reads: Cell<usize>,
	pub(super) writes: Cell<usize>,
	pub(super) barriers: Cell<usize>,
	pub(super) interrupts: Cell<u8>,
	pub(super) eof_interrupts: Cell<u8>,
	pub(super) refuse_eof: Cell<bool>,
	pub(super) extend_on_read: Cell<bool>,
	pub(super) refuse_restore: Cell<bool>,
	pub(super) refuse_inspect: Cell<bool>,
}

pub(super) struct Memory<'state> {
	pub(super) cursor: Cursor<Vec<u8>>,
	state: &'state State,
}

impl Read for Memory<'_> {
	fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
		self.state.reads.set(self.state.reads.get() + 1);
		if self.state.interrupts.get() > 0 {
			self.state.interrupts.set(self.state.interrupts.get() - 1);
			return Err(io::ErrorKind::Interrupted.into());
		}
		if self.state.extend_on_read.replace(false) {
			self.cursor.get_mut().push(0xa5);
		}
		if self.cursor.position() == u64::try_from(self.cursor.get_ref().len()).unwrap() {
			if self.state.eof_interrupts.get() > 0 {
				self.state
					.eof_interrupts
					.set(self.state.eof_interrupts.get() - 1);
				return Err(io::ErrorKind::Interrupted.into());
			}
			if self.state.refuse_eof.get() {
				return Err(io::Error::other("fixture EOF observation refused"));
			}
		}
		self.cursor.read(bytes)
	}
}

impl Write for Memory<'_> {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.state.writes.set(self.state.writes.get() + 1);
		self.cursor.write(bytes)
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

impl Seek for Memory<'_> {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		if let SeekFrom::Start(offset) = position
			&& offset != 0
			&& self.state.refuse_restore.get()
		{
			return Err(io::Error::other("fixture append cursor restore refused"));
		}
		self.cursor.seek(position)
	}
}

impl JournalSegment for Memory<'_> {
	const BARRIER: JournalFileBarrier = JournalFileBarrier::SyncAll;

	fn regular_length(&self) -> io::Result<Option<u64>> {
		if self.state.refuse_inspect.get() {
			return Err(io::Error::other("fixture metadata inspection refused"));
		}
		Ok(Some(u64::try_from(self.cursor.get_ref().len()).unwrap()))
	}

	fn sync(&self) -> io::Result<()> {
		self.state.barriers.set(self.state.barriers.get() + 1);
		Ok(())
	}
}

pub(super) fn chain(
	state: &State,
) -> (
	DurableJournal<Memory<'_>>,
	SyncedFrame,
	SyncedFrame,
	Vec<u8>,
) {
	chain_with_receipt(state, b"receipt")
}

pub(super) fn chain_with_receipt<'state>(
	state: &'state State,
	receipt: &[u8],
) -> (
	DurableJournal<Memory<'state>>,
	SyncedFrame,
	SyncedFrame,
	Vec<u8>,
) {
	let segment = Memory {
		cursor: Cursor::default(),
		state,
	};
	let mut journal = DurableJournal::from_new_segment(segment).unwrap();
	// A prefix larger than ordinary buffering makes boundary placement visible.
	let _prepared = journal
		.append(FrameKind::JobPrepared, &[0x44; 12_000])
		.unwrap();
	let start = journal.append(FrameKind::StageSealed, b"seal").unwrap();
	let offset = usize::try_from(journal.end).unwrap();
	for kind in [
		FrameKind::VerificationRecorded,
		FrameKind::MetadataRecorded,
		FrameKind::PublishIntent,
		FrameKind::PublishObserved,
		FrameKind::DurabilityRecorded,
	] {
		let _frame = journal
			.append(kind, &[u8::try_from(kind.code()).unwrap()])
			.unwrap();
	}
	let expected = journal
		.append(FrameKind::ReceiptCommitted, receipt)
		.unwrap();
	let bytes = journal.writer.as_mut().unwrap().sink_mut().cursor.get_ref()[offset..].to_vec();
	(journal, start, expected, bytes)
}
