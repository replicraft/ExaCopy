use std::{error, fmt};

/// Operand of a byte comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
	/// Left operand.
	Left,
	/// Right operand.
	Right,
}

impl fmt::Display for Side {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Left => "left",
			Self::Right => "right",
		})
	}
}

/// A comparison ended without an equality or difference result.
#[derive(Debug)]
#[non_exhaustive]
pub enum CompareError<E> {
	/// A captured length exceeds the common positioned I/O limit.
	FileTooLong {
		/// Operand with the out-of-range length.
		side: Side,
		/// Captured length in bytes.
		length: u64,
	},
	/// Scratch exceeds the per-comparison limit.
	ScratchTooLarge {
		/// Supplied scratch in bytes.
		length: usize,
	},
	/// Comparing two nonempty streams of equal length requires at least two bytes of scratch.
	InsufficientScratch,
	/// An intermediate byte range could not be represented.
	InvalidRange,
	/// The recorded observation could not be confirmed around the comparison.
	Observation {
		/// Operand whose observation was rejected.
		side: Side,
		/// Adapter error.
		source: E,
	},
	/// A positional read did not fill its entire requested buffer.
	Read {
		/// Operand whose read failed.
		side: Side,
		/// Starting byte offset of the failed request.
		offset: u64,
		/// Adapter error.
		source: E,
	},
}

impl<E: fmt::Display> fmt::Display for CompareError<E> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::FileTooLong { side, length } => {
				write!(
					formatter,
					"{side} file length {length} exceeds the supported limit"
				)
			}
			Self::ScratchTooLarge { length } => {
				write!(
					formatter,
					"comparison scratch length {length} exceeds the supported limit"
				)
			}
			Self::InsufficientScratch => {
				formatter.write_str("comparison requires two scratch bytes")
			}
			Self::InvalidRange => {
				formatter.write_str("comparison byte range cannot be represented")
			}
			Self::Observation { side, source } => {
				write!(formatter, "{side} file observation check failed ({source})")
			}
			Self::Read {
				side,
				offset,
				source,
			} => {
				write!(
					formatter,
					"{side} file read at byte {offset} failed ({source})"
				)
			}
		}
	}
}

impl<E: error::Error + 'static> error::Error for CompareError<E> {
	fn source(&self) -> Option<&(dyn error::Error + 'static)> {
		match self {
			Self::Observation { source, .. } | Self::Read { source, .. } => Some(source),
			_ => None,
		}
	}
}
