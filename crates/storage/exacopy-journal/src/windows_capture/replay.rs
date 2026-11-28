use std::io::{self, BufReader, Read, SeekFrom, Take};

use exacopy_endpoint::{JournalSegment, MAX_INTERRUPTED_RETRIES};

use crate::DurableJournalError;
use crate::frame::{ChainHead, FrameKind, FrameReader};

use super::codec::{verify_prepared, verify_range};
use super::{
	MAX_CAPTURE_SEGMENT_BYTES, MAX_PREPARED_BYTES, RANGE_BYTES, WindowsCaptureError as Error,
	WindowsCaptureInspectionError, WindowsCapturePrefix, WindowsCaptureRoles,
	WindowsCaptureSelection, payload_limit,
};

/// Reads an independently selected capture sibling at byte zero through logical EOF.
/// Each read call must return. A single bounded interruption allowance covers the whole scan.
/// The reported prefix authenticates records only. The caller owns truthful role selection,
/// native custody and physical EOF, and any actual source or stage verification.
/// # Errors
/// Reports the first invalid frame, signature, selection, torn suffix or EOF error. Any
/// included prefix ends at the last previously authenticated record.
pub fn inspect(
	segment: impl Read,
	selection: &WindowsCaptureSelection<'_>,
	observed: WindowsCaptureRoles,
) -> Result<WindowsCapturePrefix, WindowsCaptureInspectionError> {
	let mut segment = BoundedRead::new(segment, MAX_CAPTURE_SEGMENT_BYTES as u64);
	let mut prefix = None;
	let mut scan = || {
		let mut reader = FrameReader::new(&mut segment, ChainHead::start());
		let prepared = reader
			.next_frame_with_payload_limit(|kind| {
				if kind == FrameKind::WindowsCapturePrepared {
					MAX_PREPARED_BYTES
				} else {
					0
				}
			})
			.map_err(Error::Read)?
			.ok_or(Error::MissingPreparation)?;
		if prepared.kind() != FrameKind::WindowsCapturePrepared {
			return Err(Error::FrameBinding);
		}
		let extent = verify_prepared(prepared.payload(), selection, observed)?;
		let mut accepted = WindowsCapturePrefix::prepared(prepared.head(), reader.offset(), extent);
		prefix = Some(accepted);
		while let Some(position) = accepted.next_range() {
			let Some(frame) = reader
				.next_frame_with_payload_limit(|kind| {
					if kind == FrameKind::WindowsCaptureRange {
						RANGE_BYTES
					} else {
						0
					}
				})
				.map_err(Error::Read)?
			else {
				return Ok((accepted, false));
			};
			if frame.kind() != FrameKind::WindowsCaptureRange
				|| frame.head().sequence() != u64::from(position.ordinal) + 1
				|| accepted.head().sequence() != u64::from(position.ordinal)
			{
				return Err(Error::FrameBinding);
			}
			verify_range(
				frame.payload(),
				prepared.head(),
				accepted.head(),
				position,
				selection.bootstrap.owner_key(),
			)?;
			accepted.advance(frame.head(), position);
			prefix = Some(accepted);
		}
		Ok((accepted, true))
	};
	let (accepted, probe_eof) =
		scan().map_err(|source| WindowsCaptureInspectionError { prefix, source })?;
	if probe_eof && let Err(source) = terminal(&mut segment) {
		return Err(WindowsCaptureInspectionError { prefix, source });
	}
	Ok(accepted)
}

fn terminal(mut segment: impl Read) -> Result<(), Error> {
	match segment.read(&mut [0]) {
		Ok(0) => Ok(()),
		Ok(_) => Err(Error::TrailingData),
		Err(source) => Err(Error::Terminal(source)),
	}
}

// The live writer already authenticated every emitted body. This rereads the exact
// envelope chain and EOF without repeatedly verifying all earlier Ed25519 signatures.
pub(super) fn reread_boundary(
	segment: &mut impl JournalSegment,
	expected_end: u64,
) -> Result<ChainHead, DurableJournalError> {
	segment
		.seek(SeekFrom::Start(0))
		.map_err(DurableJournalError::Inspect)?;
	let bytes = BoundedRead::new(segment, expected_end);
	let mut reader = FrameReader::new(BufReader::new(bytes), ChainHead::start());
	while reader
		.next_frame_with_payload_limit(payload_limit)
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

struct BoundedRead<R> {
	input: Take<R>,
	interruptions: u8,
}

impl<R: Read> BoundedRead<R> {
	fn new(input: R, limit: u64) -> Self {
		Self {
			input: input.take(limit + 1),
			interruptions: 0,
		}
	}
}

impl<R: Read> Read for BoundedRead<R> {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		loop {
			match self.input.read(buffer) {
				Err(error) if error.kind() == io::ErrorKind::Interrupted => {
					if self.interruptions == MAX_INTERRUPTED_RETRIES {
						return Err(io::Error::other(error));
					}
					self.interruptions += 1;
				}
				other => return other,
			}
		}
	}
}
