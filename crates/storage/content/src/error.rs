use core::error::Error;
use core::fmt;

use exacopy_endpoint::MAX_FILE_LENGTH;

use crate::stream::MAX_SCRATCH_BYTES;

/// A stream length or scratch buffer outside the baseline limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamInputError {
	/// The requested stream exceeds the signed file extent limit.
	FileTooLong {
		/// Requested logical length in bytes.
		length: u64,
	},
	/// A nonempty stream requires nonempty scratch space.
	EmptyScratch,
	/// The supplied scratch buffer exceeds the baseline transfer chunk limit.
	ScratchTooLarge {
		/// Supplied buffer length in bytes.
		length: usize,
	},
}

impl fmt::Display for StreamInputError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::FileTooLong { length } => {
				write!(
					formatter,
					"stream length {length} exceeds the {MAX_FILE_LENGTH}-byte limit"
				)
			}
			Self::EmptyScratch => formatter.write_str("nonempty streams require scratch space"),
			Self::ScratchTooLarge { length } => {
				write!(
					formatter,
					"scratch length {length} exceeds the {MAX_SCRATCH_BYTES}-byte limit"
				)
			}
		}
	}
}

impl Error for StreamInputError {}

/// Why a complete stream measurement could not be produced.
#[derive(Debug)]
pub enum MeasureError<E> {
	/// The stream length or scratch buffer was rejected before I/O.
	InvalidInput(StreamInputError),
	/// The reader failed to fill a requested range.
	Read {
		/// Start of the failed range in bytes.
		offset: u64,
		/// The reader's original error.
		source: E,
	},
}

impl<E: fmt::Display> fmt::Display for MeasureError<E> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidInput(error) => fmt::Display::fmt(error, formatter),
			Self::Read { offset, source } => {
				write!(formatter, "stream read at {offset} failed: {source}")
			}
		}
	}
}

impl<E: Error + 'static> Error for MeasureError<E> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::InvalidInput(error) => Some(error),
			Self::Read { source, .. } => Some(source),
		}
	}
}

/// Why copying and measuring the complete stream could not finish.
#[derive(Debug)]
pub enum CopyMeasureError<R, W> {
	/// The stream length or scratch buffer was rejected before I/O.
	InvalidInput(StreamInputError),
	/// The source reader failed to fill a requested range.
	Read {
		/// Start of the failed range in bytes.
		offset: u64,
		/// The source reader's original error.
		source: R,
	},
	/// The stage writer failed to write a requested range in full.
	Write {
		/// Start of the failed range in bytes.
		offset: u64,
		/// The stage writer's original error.
		source: W,
	},
}

impl<R: fmt::Display, W: fmt::Display> fmt::Display for CopyMeasureError<R, W> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidInput(error) => fmt::Display::fmt(error, formatter),
			Self::Read { offset, source } => {
				write!(formatter, "source read at {offset} failed: {source}")
			}
			Self::Write { offset, source } => {
				write!(formatter, "stage write at {offset} failed: {source}")
			}
		}
	}
}

impl<R: Error + 'static, W: Error + 'static> Error for CopyMeasureError<R, W> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::InvalidInput(error) => Some(error),
			Self::Read { source, .. } => Some(source),
			Self::Write { source, .. } => Some(source),
		}
	}
}
