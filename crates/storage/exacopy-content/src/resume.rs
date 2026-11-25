use exacopy_endpoint::MAX_FILE_LENGTH;

use crate::stream::visit_between;
use crate::{
	ContentDigest, MeasureError, ResumeMeasureError, StreamInputError, validate_stream_input,
};

/// One historical range whose bytes may still be present in a retained private stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointCandidate {
	/// Absolute start of the historical range.
	pub offset: u64,
	/// Number of bytes covered by the historical digest.
	pub length: u64,
	/// Standard unkeyed BLAKE3-256 digest of those bytes in stream order.
	pub digest: [u8; 32],
}

/// Measurement of the complete fresh source stream and the bytes reused in the private stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ResumeMeasurement {
	/// Standard unkeyed BLAKE3-256 digest of the freshly read source bytes in offset order.
	pub digest: ContentDigest,
	/// Number of bytes verified against history in both streams and left unwritten.
	pub reused_bytes: u64,
}

/// Reuses freshly verified ranges in a private stage while measuring the entire source stream.
///
/// Candidates must form a contiguous nonempty-range prefix in offset order. The caller
/// binds them to the held stage and captures the stage extent before any writes. Each
/// covered range is freshly read from both streams. A range is left unwritten only when
/// both digests match its historical digest. Ranges outside the captured stage extent and
/// the suffix after the candidates are read from the source and written in full. Readers
/// and writers must transfer each requested slice exactly. All transfers use the one
/// caller-owned scratch buffer.
///
/// A range whose held stage matches history but whose source does not must be read
/// again for rewriting. Its two source digests must agree. The caller establishes
/// identity, source stability and writer quiescence and independently reads back
/// the complete stage before authorizing publication.
///
/// # Errors
/// Rejects invalid lengths, scratch sizes and candidates before I/O. Returns the first
/// callback error or disagreement between two passes over a source range. A failure can
/// leave partial writes in the private stage for the caller to reconcile.
pub fn resume_and_measure_at<S, T, W>(
	length: u64,
	stage_length: u64,
	scratch: &mut [u8],
	candidates: &[CheckpointCandidate],
	mut read_source: impl FnMut(u64, &mut [u8]) -> Result<(), S>,
	mut read_stage: impl FnMut(u64, &mut [u8]) -> Result<(), T>,
	mut write_stage: impl FnMut(u64, &[u8]) -> Result<(), W>,
) -> Result<ResumeMeasurement, ResumeMeasureError<S, T, W>> {
	let invalid_input = ResumeMeasureError::InvalidInput;
	validate_stream_input(length, scratch.len()).map_err(invalid_input)?;
	if stage_length > MAX_FILE_LENGTH {
		return Err(invalid_input(StreamInputError::FileTooLong {
			length: stage_length,
		}));
	}

	let mut prefix_end = 0;
	for candidate in candidates {
		prefix_end = candidate_end(candidate, prefix_end, length)?;
	}

	let mut read_source = |offset, bytes: &mut [u8]| {
		read_source(offset, bytes)
			.map_err(|source| ResumeMeasureError::Source(MeasureError::Read { offset, source }))
	};
	let mut write_stage = |offset, bytes: &[u8]| {
		write_stage(offset, bytes).map_err(|source| ResumeMeasureError::Write { offset, source })
	};
	let mut whole = blake3::Hasher::new();
	let mut reused_bytes = 0_u64;
	let mut start = 0;
	for candidate in candidates {
		let end = candidate_end(candidate, start, length)?;
		let mut stage_matches = false;
		if end <= stage_length {
			let mut stage = blake3::Hasher::new();
			visit_between(start, end, scratch, invalid_input, |offset, bytes| {
				read_stage(offset, bytes).map_err(|source| {
					ResumeMeasureError::Stage(MeasureError::Read { offset, source })
				})?;
				stage.update(bytes);
				Ok(())
			})?;
			stage_matches = stage.finalize().as_bytes() == &candidate.digest;
		}

		let mut source = blake3::Hasher::new();
		visit_between(start, end, scratch, invalid_input, |offset, bytes| {
			read_source(offset, bytes)?;
			source.update(bytes);
			whole.update(bytes);
			if !stage_matches {
				write_stage(offset, bytes)?;
			}
			Ok(())
		})?;
		let source_digest = source.finalize();
		if stage_matches {
			if source_digest.as_bytes() == &candidate.digest {
				reused_bytes = reused_bytes
					.checked_add(candidate.length)
					.ok_or_else(|| invalid_input(StreamInputError::FileTooLong { length }))?;
			} else {
				source.reset();
				visit_between(start, end, scratch, invalid_input, |offset, bytes| {
					read_source(offset, bytes)?;
					source.update(bytes);
					write_stage(offset, bytes)
				})?;
				if source.finalize() != source_digest {
					return Err(ResumeMeasureError::SourceChanged {
						offset: start,
						length: candidate.length,
					});
				}
			}
		}
		start = end;
	}
	visit_between(
		prefix_end,
		length,
		scratch,
		invalid_input,
		|offset, bytes| {
			read_source(offset, bytes)?;
			whole.update(bytes);
			write_stage(offset, bytes)
		},
	)?;
	Ok(ResumeMeasurement {
		digest: ContentDigest(whole.finalize()),
		reused_bytes,
	})
}

fn candidate_end<S, T, W>(
	candidate: &CheckpointCandidate,
	start: u64,
	length: u64,
) -> Result<u64, ResumeMeasureError<S, T, W>> {
	candidate
		.offset
		.checked_add(candidate.length)
		.filter(|&end| candidate.offset == start && end > start && end <= length)
		.ok_or(ResumeMeasureError::InvalidCandidate {
			offset: candidate.offset,
			length: candidate.length,
		})
}
