use crate::frame::AppendStartError;
mod error;

#[cfg(test)]
mod tests;

use std::fmt;
use std::io::{BufReader, Read as _, SeekFrom};

use exacopy_endpoint::{JournalFileBarrier, JournalSegment};

use crate::frame::{
	ChainHead, FRAME_OVERHEAD_BYTES, Frame, FrameKind, FrameReader, FrameWriteError, FrameWriter,
	MAX_PAYLOAD_BYTES,
};

pub use error::DurableJournalError;

/// Maximum size in bytes for the local first segment supported by this writer.
pub const MAX_FIRST_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

/// Owns the sole writer for a journal segment and barriers each complete frame.
pub struct DurableJournal<S> {
	writer: Option<FrameWriter<S>>,
	end: u64,
}

impl<S: JournalSegment> DurableJournal<S> {
	/// Takes an already authorized, exclusively created first segment.
	///
	/// The caller establishes creation provenance, private namespace ownership and exclusive
	/// mutation access before transferring the segment. The caller also establishes any required
	/// owner-record and directory-entry barriers. This constructor checks the segment's file type,
	/// length and cursor.
	///
	/// # Errors
	/// Fails for a nonregular or nonempty segment, a nonzero cursor, or failed inspection.
	pub fn from_new_segment(mut segment: S) -> Result<Self, DurableJournalError> {
		check_segment(&mut segment, 0)?;
		Ok(Self {
			writer: Some(FrameWriter::new(segment, ChainHead::start())),
			end: 0,
		})
	}

	/// Resumes appending to an authorized first segment after rereading and syncing it.
	///
	/// The caller supplies the pinned readable and writable segment, holds exclusive mutation
	/// access, and authenticates and semantically validates its nonempty journal prefix to
	/// establish `expected_head` and `expected_end`. The segment must use the original profile's
	/// barrier. This method verifies the envelopes and requests a fresh file barrier. The caller
	/// owns decisions about recovered effects and any required enclosing namespace barriers.
	///
	/// # Errors
	/// Fails for an empty prefix, a segment above 64 MiB, a nonregular object, a length or
	/// chain-head mismatch, a damaged or incomplete frame, or failed I/O. Segment bytes are preserved.
	pub fn resume_first_segment(
		segment: S,
		expected_head: ChainHead,
		expected_end: u64,
	) -> Result<Self, DurableJournalError> {
		Self::resume_first_segment_admitted(segment, expected_head, expected_end, || Ok(()))
	}

	/// Rechecks the exact accepted segment and enters authority before its file barrier.
	///
	/// # Errors
	/// Refuses the same invalid state as [Self::resume_first_segment], or refused admission.
	pub fn resume_first_segment_admitted<G>(
		mut segment: S,
		expected_head: ChainHead,
		expected_end: u64,
		enter: impl FnOnce() -> std::io::Result<G>,
	) -> Result<Self, DurableJournalError> {
		if expected_head == ChainHead::start() || expected_end == 0 {
			return Err(DurableJournalError::EmptyPrefix);
		}
		if expected_end > MAX_FIRST_SEGMENT_BYTES {
			return Err(DurableJournalError::SegmentTooLarge {
				length: expected_end,
				limit: MAX_FIRST_SEGMENT_BYTES,
			});
		}
		check_length(&segment, expected_end)?;
		let head = reread_boundary(&mut segment, expected_end)?;
		if head != expected_head {
			return Err(DurableJournalError::UnexpectedHead);
		}
		restore_boundary(&mut segment, expected_end)?;
		let guard = enter().map_err(DurableJournalError::Admission)?;
		segment.sync().map_err(DurableJournalError::Sync)?;
		drop(guard);
		Ok(Self {
			writer: Some(FrameWriter::new(segment, head)),
			end: expected_end,
		})
	}

	/// Rereads the held segment through the expected current synced frame and exact EOF.
	/// Success restores the append cursor. This operation performs no writes or barriers.
	/// It checks the envelope chain on this descriptor. The caller owns namespace identity,
	/// owner authentication, semantic replay and native durability qualification.
	/// # Errors
	/// Refuses an unexpected stored head or barrier without I/O or retiring the writer.
	/// Inspection, read, chain and cursor failures after a match retire the writer.
	pub fn confirm_current_frame(
		&mut self,
		expected: &SyncedFrame,
	) -> Result<(), DurableJournalError> {
		let mut writer = self.writer.take().ok_or(DurableJournalError::Retired)?;
		if writer.head() != expected.head() {
			self.writer = Some(writer);
			return Err(DurableJournalError::StaleExpectedHead);
		}
		if expected.barrier() != S::BARRIER {
			self.writer = Some(writer);
			return Err(DurableJournalError::UnexpectedBarrier {
				expected: expected.barrier(),
				actual: S::BARRIER,
			});
		}

		let segment = writer.sink_mut();
		check_segment(segment, self.end)?;
		let head = reread_boundary(segment, self.end)?;
		if head != expected.head() {
			return Err(DurableJournalError::UnexpectedHead);
		}
		restore_boundary(segment, self.end)?;
		self.writer = Some(writer);
		Ok(())
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
		self.append_admitted(kind, payload, || Ok(()))
	}

	fn append_admitted<G>(
		&mut self,
		kind: FrameKind,
		payload: &[u8],
		enter: impl FnOnce() -> std::io::Result<G>,
	) -> Result<SyncedFrame, DurableJournalError> {
		let mut writer = self.writer.take().ok_or(DurableJournalError::Retired)?;
		let Some(end) = frame_end(self.end, payload.len()) else {
			self.writer = Some(writer);
			return Err(DurableJournalError::OffsetOverflow);
		};
		check_segment(writer.sink_mut(), self.end)?;
		if payload.len() > MAX_PAYLOAD_BYTES {
			self.writer = Some(writer);
			return Err(DurableJournalError::Frame(
				FrameWriteError::PayloadTooLarge(payload.len()),
			));
		}
		if end > MAX_FIRST_SEGMENT_BYTES {
			self.writer = Some(writer);
			return Err(DurableJournalError::SegmentTooLarge {
				length: end,
				limit: MAX_FIRST_SEGMENT_BYTES,
			});
		}
		let (head, guard) = match writer.append_admitted(kind, payload, enter) {
			Ok(admitted) => admitted,
			Err(AppendStartError::Admission(error)) => {
				self.writer = Some(writer);
				return Err(DurableJournalError::Admission(error));
			}
			Err(AppendStartError::Frame(error)) => {
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
		writer
			.sink_mut()
			.sync()
			.map_err(DurableJournalError::Sync)?;
		drop(guard);
		self.end = end;
		self.writer = Some(writer);
		Ok(SyncedFrame {
			head,
			kind,
			barrier: S::BARRIER,
		})
	}

	/// Appends an owned payload and returns the exact frame and evidence of its file barrier.
	///
	/// Use this when later records must bind the accepted frame and inspect its original payload.
	/// The frame includes the writer's actual preceding digest.
	///
	/// # Errors
	/// Applies the same limits, failure behavior and prerequisites as [`Self::append`].
	pub fn append_frame(
		&mut self,
		kind: FrameKind,
		payload: Vec<u8>,
	) -> Result<(Frame, SyncedFrame), DurableJournalError> {
		self.append_frame_admitted(kind, payload, || Ok(()))
	}

	/// Appends one frame under a caller-held effect guard.
	///
	/// Admission runs after physical segment checks and frame preparation, immediately
	/// before writing. The guard covers the started frame and its file barrier.
	///
	/// # Errors
	/// A refused admission writes no bytes. All ordinary append failures remain possible.
	pub fn append_frame_admitted<G>(
		&mut self,
		kind: FrameKind,
		payload: Vec<u8>,
		enter: impl FnOnce() -> std::io::Result<G>,
	) -> Result<(Frame, SyncedFrame), DurableJournalError> {
		let previous = self
			.writer
			.as_ref()
			.ok_or(DurableJournalError::Retired)?
			.head();
		let synced = self.append_admitted(kind, &payload, enter)?;
		let frame = Frame::from_verified_parts(kind, payload, synced.head(), previous.digest());
		Ok((frame, synced))
	}
}

impl<S: JournalSegment> fmt::Debug for DurableJournal<S> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("DurableJournal")
			.field("synced_end", &self.end)
			.field("barrier", &S::BARRIER)
			.field("retired", &self.writer.is_none())
			.finish()
	}
}

/// Evidence that this writer completed a frame and the selected file barrier succeeded.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct SyncedFrame {
	head: ChainHead,
	kind: FrameKind,
	barrier: JournalFileBarrier,
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

	/// Returns the file barrier that succeeded for this frame.
	#[must_use]
	pub const fn barrier(&self) -> JournalFileBarrier {
		self.barrier
	}
}

// The caller supplies a boundary already limited to MAX_FIRST_SEGMENT_BYTES. A single extra
// byte differentiates true EOF from reaching the limit, even with the buffered reader.
fn reread_boundary(
	segment: &mut impl JournalSegment,
	expected_end: u64,
) -> Result<ChainHead, DurableJournalError> {
	segment.rewind().map_err(DurableJournalError::Inspect)?;
	let bytes = segment.take(expected_end + 1);
	let mut reader = FrameReader::new(BufReader::new(bytes), ChainHead::start());
	while reader
		.next_frame()
		.map_err(DurableJournalError::ReadFrame)?
		.is_some()
	{}
	if reader.offset() != expected_end {
		return Err(DurableJournalError::UnexpectedLength {
			expected: expected_end,
			actual: reader.offset(),
		});
	}
	Ok(reader.head())
}

fn restore_boundary(
	segment: &mut impl JournalSegment,
	end: u64,
) -> Result<(), DurableJournalError> {
	segment
		.seek(SeekFrom::Start(end))
		.map_err(DurableJournalError::Inspect)?;
	check_segment(segment, end)
}

fn frame_end(offset: u64, payload_bytes: usize) -> Option<u64> {
	let overhead = u64::try_from(FRAME_OVERHEAD_BYTES).ok()?;
	let payload_bytes = u64::try_from(payload_bytes).ok()?;
	offset.checked_add(overhead)?.checked_add(payload_bytes)
}

fn check_segment(
	segment: &mut impl JournalSegment,
	expected_end: u64,
) -> Result<(), DurableJournalError> {
	check_length(segment, expected_end)?;
	let cursor = segment
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

fn check_length(
	segment: &impl JournalSegment,
	expected_end: u64,
) -> Result<(), DurableJournalError> {
	let actual = segment
		.regular_length()
		.map_err(DurableJournalError::Inspect)?
		.ok_or(DurableJournalError::NotRegularFile)?;
	if actual != expected_end {
		return Err(DurableJournalError::UnexpectedLength {
			expected: expected_end,
			actual,
		});
	}
	Ok(())
}
