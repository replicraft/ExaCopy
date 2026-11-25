use std::fmt;
use std::io;

use crate::frame::FrameWriteError;

/// Admission or append failed for a journal file.
#[derive(Debug)]
#[non_exhaustive]
pub enum DurableJournalError {
	/// Handle metadata or cursor inspection failed.
	Inspect(io::Error),
	/// The handle did not refer to a regular file.
	NotRegularFile,
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
	/// The frame would exceed the representable journal file offset.
	OffsetOverflow,
	/// The frame was refused or its write failed.
	Frame(FrameWriteError),
	/// The complete frame's file barrier failed.
	Sync(io::Error),
	/// A previous uncertain outcome retired this writer.
	Retired,
}

impl fmt::Display for DurableJournalError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Inspect(source) => write!(formatter, "journal file inspection failed: {source}"),
			Self::NotRegularFile => formatter.write_str("journal requires a regular file"),
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
			Self::OffsetOverflow => {
				formatter.write_str("journal frame would overflow the file offset")
			}
			Self::Frame(source) => source.fmt(formatter),
			Self::Sync(source) => write!(formatter, "journal file barrier failed: {source}"),
			Self::Retired => formatter.write_str("journal writer retired pending reconciliation"),
		}
	}
}

impl std::error::Error for DurableJournalError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Inspect(source) | Self::Sync(source) => Some(source),
			Self::Frame(source) => Some(source),
			_ => None,
		}
	}
}
