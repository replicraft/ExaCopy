mod error;

#[cfg(test)]
mod tests;

use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read as _, Seek as _, SeekFrom};

use crate::frame::{
	ChainHead, FRAME_OVERHEAD_BYTES, FrameKind, FrameReader, FrameWriteError, FrameWriter,
	MAX_PAYLOAD_BYTES,
};

pub use error::DurableJournalError;

/// Owns the sole writer for a journal file and barriers each complete frame.
pub struct DurableJournal {
	writer: Option<FrameWriter<File>>,
	end: u64,
}

impl DurableJournal {
	/// Maximum size in bytes for the local first segment supported by this writer.
	pub const MAX_FIRST_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

	/// Takes an already authorized, exclusively created file for the first segment.
	///
	/// The caller establishes creation provenance, private namespace ownership and exclusive
	/// mutation access before transferring the file. The caller also establishes any required
	/// owner-record and directory-entry barriers. This constructor checks the handle's file type,
	/// length and cursor.
	///
	/// # Errors
	///
	/// Fails when the file is nonregular or nonempty, its cursor is nonzero, or inspection fails.
	pub fn from_new_file(mut file: File) -> Result<Self, DurableJournalError> {
		check_file(&mut file, 0)?;
		Ok(Self {
			writer: Some(FrameWriter::new(file, ChainHead::start())),
			end: 0,
		})
	}

	/// Resumes appending to an authorized first segment after rereading and syncing it.
	///
	/// The caller supplies the pinned, readable and writable file handle, holds exclusive
	/// mutation access, and authenticates and semantically validates its nonempty journal prefix
	/// to establish `expected_head` and `expected_end`. This method verifies the envelopes and
	/// requests a fresh file barrier. The caller owns decisions about recovered effects and
	/// any required owner-record and directory-entry barriers.
	///
	/// # Errors
	///
	/// Fails for an empty prefix, a segment above 64 MiB, a nonregular handle, a length or
	/// chain-head mismatch, a damaged or incomplete frame, or failed I/O. File bytes are preserved.
	pub fn resume_first_segment(
		file: File,
		expected_head: ChainHead,
		expected_end: u64,
	) -> Result<Self, DurableJournalError> {
		Self::resume_with_barrier(file, expected_head, expected_end, File::sync_all)
	}

	fn resume_with_barrier(
		mut file: File,
		expected_head: ChainHead,
		expected_end: u64,
		sync: impl FnOnce(&File) -> io::Result<()>,
	) -> Result<Self, DurableJournalError> {
		if expected_head == ChainHead::start() || expected_end == 0 {
			return Err(DurableJournalError::EmptyPrefix);
		}
		if expected_end > Self::MAX_FIRST_SEGMENT_BYTES {
			return Err(DurableJournalError::SegmentTooLarge {
				length: expected_end,
				limit: Self::MAX_FIRST_SEGMENT_BYTES,
			});
		}
		check_length(&file, expected_end)?;
		file.rewind().map_err(DurableJournalError::Inspect)?;
		let (head, end) = {
			// Read at most one byte past the bounded expected length to observe EOF there.
			let bytes = (&mut file).take(expected_end + 1);
			let mut reader = FrameReader::new(BufReader::new(bytes), ChainHead::start());
			while reader
				.next_frame()
				.map_err(DurableJournalError::ReadFrame)?
				.is_some()
			{}
			(reader.head(), reader.offset())
		};
		if end != expected_end {
			return Err(DurableJournalError::UnexpectedLength {
				expected: expected_end,
				actual: end,
			});
		}
		if head != expected_head {
			return Err(DurableJournalError::UnexpectedHead);
		}
		file.seek(SeekFrom::Start(end))
			.map_err(DurableJournalError::Inspect)?;
		check_file(&mut file, end)?;
		sync(&file).map_err(DurableJournalError::Sync)?;
		Ok(Self {
			writer: Some(FrameWriter::new(file, head)),
			end,
		})
	}

	/// Appends a complete frame and returns evidence of a successful file barrier.
	///
	/// The caller validates the payload and its effect binding. Journal ownership, directory
	/// persistence and backend durability qualification remain separate obligations.
	///
	/// # Errors
	///
	/// Reports a rejected frame, a frame that would exceed the segment limit, invalid file state,
	/// write failure, or barrier failure. An inspection, file-state, write or barrier failure
	/// permanently retires this writer. Any bytes that reached the file remain in place for
	/// reconciliation.
	pub fn append(
		&mut self,
		kind: FrameKind,
		payload: &[u8],
	) -> Result<SyncedFrame, DurableJournalError> {
		self.append_with_barrier(kind, payload, File::sync_all)
	}

	fn append_with_barrier(
		&mut self,
		kind: FrameKind,
		payload: &[u8],
		sync: impl FnOnce(&File) -> io::Result<()>,
	) -> Result<SyncedFrame, DurableJournalError> {
		let mut writer = self.writer.take().ok_or(DurableJournalError::Retired)?;
		let Some(end) = frame_end(self.end, payload.len()) else {
			self.writer = Some(writer);
			return Err(DurableJournalError::OffsetOverflow);
		};
		check_file(writer.sink_mut(), self.end)?;
		if payload.len() > MAX_PAYLOAD_BYTES {
			self.writer = Some(writer);
			return Err(DurableJournalError::Frame(
				FrameWriteError::PayloadTooLarge(payload.len()),
			));
		}
		if end > Self::MAX_FIRST_SEGMENT_BYTES {
			self.writer = Some(writer);
			return Err(DurableJournalError::SegmentTooLarge {
				length: end,
				limit: Self::MAX_FIRST_SEGMENT_BYTES,
			});
		}
		let head = match writer.append(kind, payload) {
			Ok(head) => head,
			Err(error) => {
				if matches!(
					error,
					FrameWriteError::PayloadTooLarge(_)
						| FrameWriteError::SequenceExhausted
						| FrameWriteError::ReservedDigest
				) {
					self.writer = Some(writer);
				}
				return Err(DurableJournalError::Frame(error));
			}
		};
		// A failed barrier can consume a delayed writeback error from the descriptor. Only
		// success restores the writer, so a later barrier cannot clear that uncertainty.
		sync(writer.sink_mut()).map_err(DurableJournalError::Sync)?;
		self.end = end;
		self.writer = Some(writer);
		Ok(SyncedFrame { head, kind })
	}
}

impl fmt::Debug for DurableJournal {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("DurableJournal")
			.field("synced_end", &self.end)
			.field("retired", &self.writer.is_none())
			.finish()
	}
}

/// Evidence that this writer completed a frame and successfully called `File::sync_all`.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct SyncedFrame {
	head: ChainHead,
	kind: FrameKind,
}

impl SyncedFrame {
	/// Returns the sequence and digest of the frame whose file barrier succeeded.
	#[must_use]
	pub const fn head(&self) -> ChainHead {
		self.head
	}

	/// Returns the kind of the frame whose file barrier succeeded.
	#[must_use]
	pub const fn kind(&self) -> FrameKind {
		self.kind
	}
}

fn frame_end(offset: u64, payload_bytes: usize) -> Option<u64> {
	let overhead = u64::try_from(FRAME_OVERHEAD_BYTES).ok()?;
	let payload_bytes = u64::try_from(payload_bytes).ok()?;
	offset.checked_add(overhead)?.checked_add(payload_bytes)
}

fn check_file(file: &mut File, expected_end: u64) -> Result<(), DurableJournalError> {
	check_length(file, expected_end)?;
	let cursor = file
		.stream_position()
		.map_err(DurableJournalError::Inspect)?;
	if cursor != expected_end {
		return Err(DurableJournalError::UnexpectedCursor {
			expected: expected_end,
			actual: cursor,
		});
	}
	Ok(())
}

fn check_length(file: &File, expected_end: u64) -> Result<(), DurableJournalError> {
	let metadata = file.metadata().map_err(DurableJournalError::Inspect)?;
	if !metadata.is_file() {
		return Err(DurableJournalError::NotRegularFile);
	}
	if metadata.len() != expected_end {
		return Err(DurableJournalError::UnexpectedLength {
			expected: expected_end,
			actual: metadata.len(),
		});
	}
	Ok(())
}
