use exacopy_endpoint::MAX_FILE_LENGTH;

use self::error::{CompareError, Side};

pub(crate) mod error;

#[cfg(test)]
mod tests;

/// Maximum total scratch for the two positional read buffers.
pub const MAX_SCRATCH_BYTES: usize = 8 * 1024 * 1024;

/// Exact byte comparison of two live-observed file views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveComparison {
	/// Every byte through the observed end compared equal in positional order.
	Equal {
		/// Recorded logical length of each view.
		length: u64,
	},
	/// A difference establishes inequality.
	Different(Difference),
}

/// A witness of inequality within the observed file views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Difference {
	/// The captured lengths differ. No data reads were needed for the decision.
	Length {
		/// Recorded length of the left view.
		left: u64,
		/// Recorded length of the right view.
		right: u64,
	},
	/// The first unequal byte in two views of the same recorded length.
	FirstByte {
		/// Zero-based byte offset. Subsequent bytes are outside the report.
		offset: u64,
	},
}

pub(crate) trait ReadView {
	type Error;

	fn length(&self) -> u64;

	fn recheck_observation(&self) -> Result<(), Self::Error>;

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error>;
}

pub(crate) fn compare_views<V: ReadView>(
	left: &V,
	right: &V,
	scratch: &mut [u8],
) -> Result<LiveComparison, CompareError<V::Error>> {
	let left_len = left.length();
	let right_len = right.length();
	for (side, length) in [(Side::Left, left_len), (Side::Right, right_len)] {
		if length > MAX_FILE_LENGTH {
			return Err(CompareError::FileTooLong { side, length });
		}
	}
	if scratch.len() > MAX_SCRATCH_BYTES {
		return Err(CompareError::ScratchTooLarge {
			length: scratch.len(),
		});
	}
	if left_len == right_len && left_len != 0 && scratch.len() < 2 {
		return Err(CompareError::InsufficientScratch);
	}

	recheck_views(left, right)?;
	let comparison = if left_len == right_len {
		compare_bytes(left, right, left_len, scratch)?
	} else {
		LiveComparison::Different(Difference::Length {
			left: left_len,
			right: right_len,
		})
	};
	recheck_views(left, right)?;
	Ok(comparison)
}

fn recheck_views<V: ReadView>(left: &V, right: &V) -> Result<(), CompareError<V::Error>> {
	for (side, view) in [(Side::Left, left), (Side::Right, right)] {
		view.recheck_observation()
			.map_err(|source| CompareError::Observation { side, source })?;
	}
	Ok(())
}

fn compare_bytes<V: ReadView>(
	left: &V,
	right: &V,
	length: u64,
	scratch: &mut [u8],
) -> Result<LiveComparison, CompareError<V::Error>> {
	let (left_buffer, right_buffer) = scratch.split_at_mut(scratch.len() / 2);
	let width = u64::try_from(left_buffer.len()).map_err(|_| CompareError::InvalidRange)?;
	let mut offset = 0;
	while offset < length {
		let count = width.min(length - offset);
		let next = offset
			.checked_add(count)
			.ok_or(CompareError::InvalidRange)?;
		let count = usize::try_from(count).map_err(|_| CompareError::InvalidRange)?;
		let left_chunk = &mut left_buffer[..count];
		let right_chunk = &mut right_buffer[..count];
		for (side, view, buffer) in [
			(Side::Left, left, &mut *left_chunk),
			(Side::Right, right, &mut *right_chunk),
		] {
			view.read_exact_at(offset, buffer)
				.map_err(|source| CompareError::Read {
					side,
					offset,
					source,
				})?;
		}
		if let Some(index) = left_chunk
			.iter()
			.zip(right_chunk)
			.position(|(left, right)| left != right)
		{
			let index = u64::try_from(index).map_err(|_| CompareError::InvalidRange)?;
			let offset = offset
				.checked_add(index)
				.ok_or(CompareError::InvalidRange)?;
			return Ok(LiveComparison::Different(Difference::FirstByte { offset }));
		}
		offset = next;
	}
	Ok(LiveComparison::Equal { length })
}
