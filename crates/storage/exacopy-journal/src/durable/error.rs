use std::fmt;
use std::io;

use exacopy_endpoint::JournalFileBarrier;

use crate::frame::{FrameReadError, FrameWriteError};

/// Admission or append failed for a journal file.
#[derive(Debug)]
#[non_exhaustive]
pub enum DurableJournalError {
	/// Admission refused before the first write of the selected frame.
	Admission(io::Error),
	/// Handle metadata or cursor inspection failed.
	Inspect(io::Error),
	/// The handle did not refer to a regular file.
	NotRegularFile,
	/// The supplied resume boundary does not identify an existing frame.
	EmptyPrefix,
	/// The supplied or prospective segment length exceeded the limit.
	SegmentTooLarge {
		/// Supplied or prospective segment length in bytes.
		length: u64,
		/// Maximum accepted length in bytes.
		limit: u64,
	},
	/// The file length differed from the current accepted boundary.
	UnexpectedLength {
		/// Expected file length in bytes.
		expected: u64,
		/// Observed file length in bytes.
		actual: u64,
	},
	/// The write cursor differed from the current accepted boundary.
	UnexpectedCursor {
		/// Expected cursor position in bytes.
		expected: u64,
		/// Observed cursor position in bytes.
		actual: u64,
	},
	/// The caller supplied a stale head to the held writer. The segment was not inspected.
	StaleExpectedHead,
	/// The requested suffix storage or sequence bounds were invalid before I/O.
	InvalidSuffixRequest,
	/// The selected start token was absent or had a different frame kind.
	SuffixAnchorNotFound,
	/// Literal suffix bytes exceeded the caller storage, bounded to 4096 bytes.
	SuffixTooLarge,
	/// A physical byte was observed after the confirmed terminal suffix frame.
	TrailingSuffixData {
		/// First unexpected byte offset, without asserting the complete file length.
		offset: u64,
	},
	/// The reread verified head differed from the supplied head.
	UnexpectedHead,
	/// An existing frame could not be read or verified.
	ReadFrame(FrameReadError),
	/// The frame would exceed the representable journal file offset.
	OffsetOverflow,
	/// The frame was refused or its write failed.
	Frame(FrameWriteError),
	/// The supplied segment does not perform the required file barrier.
	UnexpectedBarrier {
		/// Barrier required by the admitted workflow profile.
		expected: JournalFileBarrier,
		/// Barrier performed by the supplied segment.
		actual: JournalFileBarrier,
	},
	/// The journal file barrier failed.
	Sync(io::Error),
	/// A previous uncertain outcome retired this writer.
	Retired,
}

impl fmt::Display for DurableJournalError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Admission(source) => write!(formatter, "journal effect was refused: {source}"),
			Self::Inspect(source) => write!(formatter, "journal file inspection failed: {source}"),
			Self::NotRegularFile => formatter.write_str("journal requires a regular file"),
			Self::EmptyPrefix => formatter.write_str("journal resume requires an existing frame"),
			Self::SegmentTooLarge { length, limit } => {
				write!(
					formatter,
					"journal segment is {length} bytes, limit is {limit}"
				)
			}
			Self::UnexpectedLength { expected, actual } => {
				write!(
					formatter,
					"journal length is {actual} bytes, expected {expected}"
				)
			}
			Self::UnexpectedCursor { expected, actual } => {
				write!(
					formatter,
					"journal cursor is at byte {actual}, expected {expected}"
				)
			}
			Self::StaleExpectedHead => {
				formatter.write_str("expected head differs from the writer's current head")
			}
			Self::InvalidSuffixRequest => formatter.write_str("invalid journal suffix request"),
			Self::SuffixAnchorNotFound => {
				formatter.write_str("journal suffix anchor was not found")
			}
			Self::SuffixTooLarge => formatter.write_str("journal suffix exceeded bounded output"),
			Self::TrailingSuffixData { offset } => {
				write!(
					formatter,
					"journal has data after the confirmed suffix at byte {offset}"
				)
			}
			Self::UnexpectedHead => {
				formatter.write_str("journal head differs from the expected head")
			}
			Self::ReadFrame(source) => source.fmt(formatter),
			Self::OffsetOverflow => {
				formatter.write_str("journal frame would overflow the file offset")
			}
			Self::Frame(source) => source.fmt(formatter),
			Self::UnexpectedBarrier { expected, actual } => {
				write!(
					formatter,
					"journal barrier is {actual:?}, expected {expected:?}"
				)
			}
			Self::Sync(source) => write!(formatter, "journal file barrier failed: {source}"),
			Self::Retired => formatter.write_str("journal writer retired pending reconciliation"),
		}
	}
}

impl std::error::Error for DurableJournalError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Admission(source) | Self::Inspect(source) | Self::Sync(source) => Some(source),
			Self::ReadFrame(source) => Some(source),
			Self::Frame(source) => Some(source),
			_ => None,
		}
	}
}
