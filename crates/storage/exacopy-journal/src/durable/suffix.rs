use std::cell::Cell;
use std::io::{self, Read};

use exacopy_endpoint::JournalSegment;

use super::{DurableJournal, DurableJournalError, SyncedFrame, check_segment, restore_boundary};
use crate::frame::{ChainHead, FrameReader};

#[cfg(test)]
mod tests;

const MAX_SUFFIX_BYTES: usize = 4096;
const INTERRUPTED_READ_ALLOWANCE: u8 = 16;

impl<S: JournalSegment> DurableJournal<S> {
	/// Confirms the complete held chain and returns its literal bytes after `start`.
	///
	/// Reads the original descriptor without buffering ahead of frame boundaries.
	/// The matching start frame is excluded. At most 4096 suffix bytes and one
	/// physical EOF probe are accepted, under the existing full-segment limit.
	/// All reads share sixteen retries for interrupted calls. Each call must return.
	/// Success restores the append cursor before changing `output`. No writes or
	/// barriers occur. The caller authenticates the owner, selects the actual
	/// start token and validates the returned payloads and native custody.
	///
	/// # Errors
	/// A stale current token, incompatible barrier, reversed sequence or oversized
	/// output refuses without I/O and preserves writer usability. After that
	/// admission, any inspection, anchor, capacity, chain, EOF or restore failure
	/// retires the writer. Every error leaves the caller's output unchanged.
	pub fn confirm_current_suffix(
		&mut self,
		start: &SyncedFrame,
		expected: &SyncedFrame,
		output: &mut [u8],
	) -> Result<usize, DurableJournalError> {
		let mut writer = self.writer.take().ok_or(DurableJournalError::Retired)?;
		if writer.head() != expected.head() {
			self.writer = Some(writer);
			return Err(DurableJournalError::StaleExpectedHead);
		}
		for frame in [start, expected] {
			if frame.barrier() != S::BARRIER {
				self.writer = Some(writer);
				return Err(DurableJournalError::UnexpectedBarrier {
					expected: frame.barrier(),
					actual: S::BARRIER,
				});
			}
		}
		if output.len() > MAX_SUFFIX_BYTES || start.head().sequence() > expected.head().sequence() {
			self.writer = Some(writer);
			return Err(DurableJournalError::InvalidSuffixRequest);
		}
		let segment = writer.sink_mut();
		check_segment(segment, self.end)?;
		let mut scratch = [0; MAX_SUFFIX_BYTES];
		let length = read_suffix(
			segment,
			self.end,
			start,
			expected,
			&mut scratch[..output.len()],
		)?;
		restore_boundary(segment, self.end)?;
		output[..length].copy_from_slice(&scratch[..length]);
		self.writer = Some(writer);
		Ok(length)
	}
}

fn read_suffix(
	segment: &mut impl JournalSegment,
	end: u64,
	start: &SyncedFrame,
	expected: &SyncedFrame,
	output: &mut [u8],
) -> Result<usize, DurableJournalError> {
	segment.rewind().map_err(DurableJournalError::Inspect)?;
	let capturing = Cell::new(false);
	let exceeded = Cell::new(false);
	let mut tap = SuffixRead {
		reader: segment.take(end + 1),
		capturing: &capturing,
		exceeded: &exceeded,
		output,
		used: 0,
		interruptions: INTERRUPTED_READ_ALLOWANCE,
	};
	let mut found_start = false;
	{
		let mut frames = FrameReader::new(&mut tap, ChainHead::start());
		loop {
			let frame = frames
				.next_frame()
				.map_err(|error| {
					if exceeded.get() {
						DurableJournalError::SuffixTooLarge
					} else {
						DurableJournalError::ReadFrame(error)
					}
				})?
				.ok_or(DurableJournalError::UnexpectedHead)?;
			if frame.head() == start.head() {
				if frame.kind() != start.kind() {
					return Err(DurableJournalError::SuffixAnchorNotFound);
				}
				// FrameReader has consumed exactly this frame: the next raw read
				// begins at the suffix, rather than a buffer's read-ahead boundary.
				capturing.set(true);
				found_start = true;
			}
			if frame.head() == expected.head() {
				if frame.kind() != expected.kind() {
					return Err(DurableJournalError::UnexpectedHead);
				}
				capturing.set(false);
				break;
			}
		}
		if frames.offset() != end {
			return Err(DurableJournalError::UnexpectedLength {
				expected: end,
				actual: frames.offset(),
			});
		}
	}
	if !found_start {
		return Err(DurableJournalError::SuffixAnchorNotFound);
	}
	// Unbuffered parsing consumed exactly `end` bytes. Take still permits
	// one physical byte, and the same tap owns the shared interruption budget.
	let mut probe = [0];
	if tap.read(&mut probe).map_err(|source| {
		DurableJournalError::ReadFrame(crate::frame::FrameReadError::Io {
			offset: end,
			source,
		})
	})? != 0
	{
		return Err(DurableJournalError::TrailingSuffixData { offset: end });
	}
	Ok(tap.used)
}

struct SuffixRead<'buffer, R> {
	reader: R,
	capturing: &'buffer Cell<bool>,
	exceeded: &'buffer Cell<bool>,
	output: &'buffer mut [u8],
	used: usize,
	interruptions: u8,
}

impl<R: Read> Read for SuffixRead<'_, R> {
	fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
		if output.is_empty() {
			return Ok(0);
		}
		let count = loop {
			match self.reader.read(output) {
				Err(error) if error.kind() == io::ErrorKind::Interrupted => {
					if self.interruptions == 0 {
						// Prevent FrameReader or read_exact from retrying forever.
						return Err(io::Error::other(error));
					}
					self.interruptions -= 1;
				}
				result => break result?,
			}
		};
		if count > output.len() {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"invalid read count",
			));
		}
		if self.capturing.get() {
			let Some(end) = self
				.used
				.checked_add(count)
				.filter(|&end| end <= self.output.len())
			else {
				self.exceeded.set(true);
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					"journal suffix exceeds output",
				));
			};
			self.output[self.used..end].copy_from_slice(&output[..count]);
			self.used = end;
		}
		Ok(count)
	}
}
