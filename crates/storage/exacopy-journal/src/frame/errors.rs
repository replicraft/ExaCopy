use std::{fmt, io};

/// An envelope violated a version, integrity, chain, or size rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameProblem {
	/// The magic bytes differ from the version 1 journal magic.
	Magic,
	/// This reader cannot interpret the envelope version.
	UnsupportedVersion(u16),
	/// The record kind has no known allocation.
	UnsupportedKind(u16),
	/// The payload length exceeds the format limit.
	PayloadTooLarge(u32),
	/// The sequence failed to start at one or increase.
	Sequence(u64),
	/// The record did not chain to the preceding digest.
	PreviousDigest,
	/// The stored checksum differs from the computed CRC32C.
	Checksum,
	/// The stored digest differs from the computed BLAKE3 digest or is reserved.
	Digest,
	/// The segment offset could not represent the next record boundary.
	OffsetOverflow,
}

/// A scan ended without a complete verified frame.
#[derive(Debug)]
pub enum FrameReadError {
	/// EOF followed a structurally plausible prefix of an incomplete frame.
	TornTail {
		/// Offset of the frame's first byte in this segment.
		offset: u64,
		/// Number of bytes read from the incomplete frame.
		bytes_read: usize,
	},
	/// The frame contained incompatible or damaged bytes.
	Corrupt {
		/// Offset of the frame's first byte in this segment.
		offset: u64,
		/// Reason the frame was refused.
		problem: FrameProblem,
	},
	/// The stream did not supply a reliable observation of EOF or frame bytes.
	Io {
		/// Offset of the frame's first byte in this segment.
		offset: u64,
		/// Underlying read error.
		source: io::Error,
	},
	/// A previous terminal error stopped this reader.
	Stopped,
}

impl fmt::Display for FrameReadError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::TornTail { offset, bytes_read } => {
				write!(
					formatter,
					"incomplete journal frame at {offset} after {bytes_read} bytes"
				)
			}
			Self::Corrupt { offset, problem } => {
				write!(formatter, "invalid journal frame at {offset} ({problem:?})")
			}
			Self::Io { offset, source } => {
				write!(
					formatter,
					"journal read failed for frame at {offset}: {source}"
				)
			}
			Self::Stopped => formatter.write_str("journal reader stopped after a previous error"),
		}
	}
}

impl std::error::Error for FrameReadError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Io { source, .. } => Some(source),
			_ => None,
		}
	}
}

/// A frame append could not complete.
#[derive(Debug)]
pub enum FrameWriteError {
	/// No frame bytes were submitted because the payload exceeded the size limit.
	PayloadTooLarge(usize),
	/// No frame bytes were submitted because the chain has no remaining sequence numbers.
	SequenceExhausted,
	/// No frame bytes were submitted because the digest matched the reserved chain anchor.
	ReservedDigest,
	/// The stream may have accepted a partial frame.
	Io(io::Error),
	/// A previous append encountered an I/O error and stopped this writer.
	Stopped,
}

impl fmt::Display for FrameWriteError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::PayloadTooLarge(bytes) => {
				write!(formatter, "journal payload too large ({bytes} bytes)")
			}
			Self::SequenceExhausted => formatter.write_str("journal sequence exhausted"),
			Self::ReservedDigest => {
				formatter.write_str("journal frame produced the reserved zero digest")
			}
			Self::Io(source) => write!(formatter, "journal append failed: {source}"),
			Self::Stopped => {
				formatter.write_str("journal writer stopped after a previous append error")
			}
		}
	}
}

impl std::error::Error for FrameWriteError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Io(source) => Some(source),
			_ => None,
		}
	}
}
