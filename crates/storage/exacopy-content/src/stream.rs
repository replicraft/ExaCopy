use exacopy_endpoint::MAX_FILE_LENGTH;

use crate::{ContentDigest, CopyMeasureError, MeasureError, StreamInputError};

/// Largest scratch buffer accepted by the baseline sequential transfer.
pub const MAX_SCRATCH_BYTES: usize = 4 * 1024 * 1024;

/// Checks the stream and scratch limits before a caller creates a private stage.
///
/// # Errors
/// Returns the rejected length or scratch constraint. An empty stream may use
/// empty scratch space.
pub fn validate_stream_input(length: u64, scratch_len: usize) -> Result<(), StreamInputError> {
	if length > MAX_FILE_LENGTH {
		return Err(StreamInputError::FileTooLong { length });
	}
	if scratch_len > MAX_SCRATCH_BYTES {
		return Err(StreamInputError::ScratchTooLarge {
			length: scratch_len,
		});
	}
	if length != 0 && scratch_len == 0 {
		return Err(StreamInputError::EmptyScratch);
	}
	Ok(())
}

/// Measures one logical stream with standard, unkeyed BLAKE3-256.
///
/// The callback must fill each requested range exactly, including zeros read
/// from sparse regions. Calls cover the stream in order from byte zero. An empty
/// stream invokes no callbacks and accepts an empty scratch buffer.
///
/// # Errors
/// Rejects lengths above the signed file extent limit and invalid scratch sizes.
/// Returns the first read error with the starting position of its requested range.
pub fn measure_at<E>(
	length: u64,
	scratch: &mut [u8],
	mut read: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<ContentDigest, MeasureError<E>> {
	stream_at(
		length,
		scratch,
		MeasureError::InvalidInput,
		|offset, chunk| read(offset, chunk).map_err(|source| MeasureError::Read { offset, source }),
	)
}

/// Copies a logical source stream to a private stage while measuring its bytes.
///
/// The read callback must fill the supplied range exactly, and the write callback
/// must write those bytes in full at the same position. A completed copy measures
/// the bytes observed from the source. The caller uses an independent read-back
/// to verify the stage and establishes authority, stability and durability.
///
/// # Errors
/// Rejects lengths above the signed file extent limit and invalid scratch sizes.
/// Returns the first read or write error. A failed transfer can leave a prefix in
/// the private stage. The caller retains it for reconciliation.
pub fn copy_and_measure_at<R, W>(
	length: u64,
	scratch: &mut [u8],
	mut read: impl FnMut(u64, &mut [u8]) -> Result<(), R>,
	mut write: impl FnMut(u64, &[u8]) -> Result<(), W>,
) -> Result<ContentDigest, CopyMeasureError<R, W>> {
	stream_at(
		length,
		scratch,
		CopyMeasureError::InvalidInput,
		|offset, chunk| {
			read(offset, chunk).map_err(|source| CopyMeasureError::Read { offset, source })?;
			write(offset, chunk).map_err(|source| CopyMeasureError::Write { offset, source })
		},
	)
}

fn stream_at<E>(
	length: u64,
	scratch: &mut [u8],
	invalid_input: fn(StreamInputError) -> E,
	mut transfer: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<ContentDigest, E> {
	validate_stream_input(length, scratch.len()).map_err(invalid_input)?;
	let mut hasher = blake3::Hasher::new();
	visit_between(0, length, scratch, invalid_input, |offset, chunk| {
		transfer(offset, chunk)?;
		hasher.update(chunk);
		Ok(())
	})?;
	Ok(ContentDigest(hasher.finalize()))
}

pub(super) fn visit_between<E>(
	mut offset: u64,
	end: u64,
	scratch: &mut [u8],
	invalid_input: fn(StreamInputError) -> E,
	mut visit: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<(), E> {
	let scratch_len = scratch.len();
	let invalid_length = || invalid_input(StreamInputError::FileTooLong { length: end });
	let invalid_scratch = || {
		invalid_input(StreamInputError::ScratchTooLarge {
			length: scratch_len,
		})
	};
	let width = u64::try_from(scratch_len).map_err(|_| invalid_scratch())?;
	while offset < end {
		let bytes = width.min(end - offset);
		let next = offset.checked_add(bytes).ok_or_else(invalid_length)?;
		let count = usize::try_from(bytes).map_err(|_| invalid_scratch())?;
		visit(offset, &mut scratch[..count])?;
		offset = next;
	}
	Ok(())
}
