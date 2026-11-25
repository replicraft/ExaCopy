use std::{fmt, io};

use exacopy_model::checked_range_end;

/// The maximum file extent supported by the common positioned I/O baseline.
pub const MAX_FILE_LENGTH: u64 = i64::MAX.cast_unsigned();

/// Consecutive interruption retries allowed at a position before returning the OS error.
pub const MAX_INTERRUPTED_RETRIES: u8 = 16;

/// Completes a positional read, passing only the unread part of `buffer` to each operation.
///
/// The operation must report transferred bytes and may return `Interrupted` only when that call
/// made no progress. On error, a prefix of `buffer` may have been changed.
///
/// # Errors
/// Rejects ranges outside the signed offset limit before I/O. EOF before the requested end,
/// impossible transfer counts, and system failures, including exhausted retries, return an error.
pub fn read_exact_at(
	offset: u64,
	buffer: &mut [u8],
	mut read: impl FnMut(u64, &mut [u8]) -> io::Result<usize>,
) -> Result<(), IoError> {
	complete(offset, buffer.len(), Operation::Read, |position, done| {
		read(position, &mut buffer[done..])
	})
}

/// Completes a positional write, passing only the unwritten part of `buffer` to each operation.
///
/// The operation must report transferred bytes and may return `Interrupted` only when that call
/// made no progress. A failure can leave a prefix written. The adapter retains the private stage
/// and the caller must decide how to verify or reconcile it.
///
/// # Errors
/// Rejects ranges outside the signed offset limit before I/O. Zero progress, impossible transfer
/// counts, and system failures, including exhausted retries, return an error.
pub fn write_all_at(
	offset: u64,
	buffer: &[u8],
	mut write: impl FnMut(u64, &[u8]) -> io::Result<usize>,
) -> Result<(), IoError> {
	complete(offset, buffer.len(), Operation::Write, |position, done| {
		write(position, &buffer[done..])
	})
}

fn complete(
	offset: u64,
	length: usize,
	kind: Operation,
	mut transfer: impl FnMut(u64, usize) -> io::Result<usize>,
) -> Result<(), IoError> {
	let invalid_range = || IoError::InvalidRange { offset, length };
	let byte_count = u64::try_from(length).map_err(|_| invalid_range())?;
	if offset > MAX_FILE_LENGTH
		|| (byte_count != 0 && checked_range_end(MAX_FILE_LENGTH, offset, byte_count).is_none())
	{
		return Err(invalid_range());
	}

	let mut done = 0;
	let mut interrupted = 0;
	while done < length {
		let transferred = u64::try_from(done).map_err(|_| invalid_range())?;
		let position = offset.checked_add(transferred).ok_or_else(invalid_range)?;
		let remaining = length - done;
		match transfer(position, done) {
			Ok(0) => return Err(kind.no_progress(position)),
			Ok(count) if count > remaining => {
				return Err(IoError::InvalidTransferCount {
					offset: position,
					count,
					remaining,
				});
			}
			Ok(count) => {
				done = done.checked_add(count).ok_or_else(invalid_range)?;
				interrupted = 0;
			}
			Err(source)
				if source.kind() == io::ErrorKind::Interrupted
					&& interrupted < MAX_INTERRUPTED_RETRIES =>
			{
				interrupted += 1;
			}
			Err(source) => {
				return Err(IoError::System {
					offset: position,
					source,
				});
			}
		}
	}
	Ok(())
}

enum Operation {
	Read,
	Write,
}

impl Operation {
	const fn no_progress(&self, offset: u64) -> IoError {
		match self {
			Self::Read => IoError::UnexpectedEof { offset },
			Self::Write => IoError::WriteZero { offset },
		}
	}
}

/// A failed positioned operation. The offset identifies the first position without confirmed progress.
#[derive(Debug)]
pub enum IoError {
	/// The requested range is outside the signed file offset limit.
	InvalidRange {
		/// Requested starting position in bytes.
		offset: u64,
		/// Requested byte count.
		length: usize,
	},
	/// The reader reached the end of the file before completing the range.
	UnexpectedEof {
		/// Position at which the adapter observed EOF.
		offset: u64,
	},
	/// The writer returned a successful count of zero while bytes remained.
	WriteZero {
		/// Position at which the writer made no progress.
		offset: u64,
	},
	/// The adapter reported a count larger than the supplied buffer suffix.
	InvalidTransferCount {
		/// Position supplied to the adapter.
		offset: u64,
		/// Count reported by the adapter.
		count: usize,
		/// Length of the supplied suffix.
		remaining: usize,
	},
	/// The backend returned an unrecoverable error or exhausted interrupted-call retries.
	System {
		/// Position of the failed call.
		offset: u64,
		/// Underlying backend error.
		source: io::Error,
	},
}

impl fmt::Display for IoError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidRange { offset, length } => write!(
				formatter,
				"{length} bytes at offset {offset} exceed the file extent limit"
			),
			Self::UnexpectedEof { offset } => {
				write!(formatter, "unexpected end of file at offset {offset}")
			}
			Self::WriteZero { offset } => {
				write!(formatter, "write made no progress at offset {offset}")
			}
			Self::InvalidTransferCount {
				offset,
				count,
				remaining,
			} => write!(
				formatter,
				"positioned operation at {offset} reported {count} bytes with {remaining} remaining"
			),
			Self::System { offset, source } => write!(
				formatter,
				"positioned operation at {offset} failed with {source}"
			),
		}
	}
}

impl core::error::Error for IoError {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			Self::System { source, .. } => Some(source),
			_ => None,
		}
	}
}
