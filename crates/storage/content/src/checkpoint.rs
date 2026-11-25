use std::time::{Duration, Instant};

use crate::{ContentDigest, CopyMeasureError, StreamInputError, validate_stream_input};

/// The sequential checkpoint defaults, bounded to leave room for final journal records.
const BASELINE_CADENCE: CheckpointCadence = CheckpointCadence {
	bytes: 64 * 1024 * 1024,
	elapsed: Duration::from_secs(2),
	limit: 4096,
};

#[derive(Clone, Copy)]
struct CheckpointCadence {
	bytes: u64,
	elapsed: Duration,
	limit: u16,
}

/// The standard BLAKE3-256 measurement of one consecutive checkpoint subrange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RangeMeasurement {
	/// Logical start offset of the measured subrange.
	pub offset: u64,
	/// Number of bytes covered by the measurement.
	pub length: u64,
	/// Unkeyed digest of the subrange bytes in stream order.
	pub digest: ContentDigest,
}

/// Copies and measures one logical source stream, offering bounded range checkpoints.
///
/// The reader fills each requested range exactly. The admission callback writes the
/// supplied bytes in full at the given offset. If it receives a range measurement,
/// it must finish that write before flushing the stage and persisting any checkpoint
/// evidence. The callback completes before the next read begins. The caller owns
/// durability, identity binding and independent read-back of the private stage.
///
/// Checkpoints cover consecutive nonempty subranges. Each ends at 64 MiB or after
/// a complete read at least two seconds after the range began, whichever comes
/// first. The clock restarts after each successful checkpoint callback. The final
/// remainder is checkpointed if it reaches a threshold. After 4096 checkpoints,
/// the remaining copy continues with whole-stream measurement alone. An empty
/// stream invokes no callbacks. The result is the standard digest of the entire
/// source stream.
///
/// # Errors
/// Rejects invalid stream lengths and scratch sizes before I/O. Returns the first
/// read or admission error, with the latter reported as a write error. Either failure
/// can leave a partial copy in the private stage for the caller to reconcile.
pub fn copy_and_checkpoint_at<R, C>(
	length: u64,
	scratch: &mut [u8],
	read: impl FnMut(u64, &mut [u8]) -> Result<(), R>,
	admit: impl FnMut(u64, &[u8], Option<RangeMeasurement>) -> Result<(), C>,
) -> Result<ContentDigest, CopyMeasureError<R, C>> {
	copy_with_cadence(length, scratch, read, admit, BASELINE_CADENCE, Instant::now)
}

fn copy_with_cadence<R, C>(
	length: u64,
	scratch: &mut [u8],
	mut read: impl FnMut(u64, &mut [u8]) -> Result<(), R>,
	mut admit: impl FnMut(u64, &[u8], Option<RangeMeasurement>) -> Result<(), C>,
	cadence: CheckpointCadence,
	mut now: impl FnMut() -> Instant,
) -> Result<ContentDigest, CopyMeasureError<R, C>> {
	let scratch_len = scratch.len();
	validate_stream_input(length, scratch_len).map_err(CopyMeasureError::InvalidInput)?;
	let invalid_scratch = || {
		CopyMeasureError::InvalidInput(StreamInputError::ScratchTooLarge {
			length: scratch_len,
		})
	};
	let width = u64::try_from(scratch_len).map_err(|_| invalid_scratch())?;
	let mut whole = blake3::Hasher::new();
	let mut range = blake3::Hasher::new();
	let mut remaining_checkpoints = cadence.limit;
	let mut range_started_at = now();
	let mut range_start = 0;
	let mut offset = 0;
	while offset < length {
		let remaining = length - offset;
		let mut bytes = width.min(remaining);
		if remaining_checkpoints > 0 {
			bytes = bytes.min(cadence.bytes - (offset - range_start));
		}
		let next = offset
			.checked_add(bytes)
			.ok_or(CopyMeasureError::InvalidInput(
				StreamInputError::FileTooLong { length },
			))?;
		let count = usize::try_from(bytes).map_err(|_| invalid_scratch())?;
		let chunk = &mut scratch[..count];
		read(offset, chunk).map_err(|source| CopyMeasureError::Read { offset, source })?;

		let mut checkpoint = None;
		if remaining_checkpoints > 0 {
			let elapsed = now().duration_since(range_started_at);
			let range_length = next - range_start;
			range.update(chunk);
			if range_length == cadence.bytes || elapsed >= cadence.elapsed {
				checkpoint = Some(RangeMeasurement {
					offset: range_start,
					length: range_length,
					digest: ContentDigest(range.finalize()),
				});
			}
		}
		admit(offset, chunk, checkpoint)
			.map_err(|source| CopyMeasureError::Write { offset, source })?;
		whole.update(chunk);

		if checkpoint.is_some() {
			remaining_checkpoints -= 1;
			range_start = next;
			range.reset();
			range_started_at = now();
		}
		offset = next;
	}
	Ok(ContentDigest(whole.finalize()))
}

#[cfg(test)]
mod tests {
	use std::cell::Cell;
	use std::convert::Infallible;
	use std::io;

	use super::*;

	#[test]
	fn checkpoints_follow_time_and_byte_boundaries_before_the_limit() {
		let source = b"abcdefghijklmnopqrstuvw";
		let start = Instant::now();
		let elapsed = Cell::new(Duration::ZERO);
		let mut next_read = 0;
		let mut writes = Vec::new();
		let mut read_ranges = Vec::new();
		let mut checkpoints = Vec::new();
		let cadence = CheckpointCadence {
			bytes: 7,
			elapsed: Duration::from_secs(2),
			limit: 3,
		};
		let result = copy_with_cadence::<Infallible, Infallible>(
			source.len() as u64,
			&mut [0; 3],
			|offset, chunk| {
				assert_eq!(offset, next_read, "reader consumes each byte exactly once");
				let begin = usize::try_from(offset).unwrap();
				chunk.copy_from_slice(&source[begin..begin + chunk.len()]);
				read_ranges.push((offset, chunk.len()));
				next_read += chunk.len() as u64;
				let span = match offset {
					0 | 3 => Duration::from_secs(1),
					13.. => Duration::from_secs(2),
					_ => Duration::from_millis(250),
				};
				elapsed.set(elapsed.get() + span);
				Ok(())
			},
			|offset, bytes, checkpoint| {
				assert_eq!(
					offset,
					writes.len() as u64,
					"writes follow the source order"
				);
				writes.extend_from_slice(bytes);
				if let Some(checkpoint) = checkpoint {
					assert_eq!(
						checkpoint.offset + checkpoint.length,
						writes.len() as u64,
						"checkpoint evidence ends with the admitted chunk"
					);
					checkpoints.push(checkpoint);
					elapsed.set(elapsed.get() + Duration::from_secs(30));
				}
				Ok(())
			},
			cadence,
			|| start + elapsed.get(),
		)
		.unwrap();

		assert_eq!(writes, source);
		assert_eq!(result.as_bytes(), blake3::hash(source).as_bytes());
		assert_eq!(
			read_ranges,
			[
				(0, 3),
				(3, 3),
				(6, 3),
				(9, 3),
				(12, 1),
				(13, 3),
				(16, 3),
				(19, 3),
				(22, 1)
			]
		);
		let expected = [(0, 6), (6, 13), (13, 16)].map(|(begin, end)| RangeMeasurement {
			offset: begin as u64,
			length: (end - begin) as u64,
			digest: ContentDigest(blake3::hash(&source[begin..end])),
		});
		assert_eq!(checkpoints, expected);
	}

	#[test]
	fn final_remainder_needs_a_threshold_and_empty_stream_has_no_io() {
		let start = Instant::now();
		for (length, elapsed, expected_checkpoint) in [
			(0, Duration::from_secs(2), false),
			(1, Duration::from_millis(1999), false),
			(1, Duration::from_secs(2), true),
		] {
			let mut ticks = [start, start + elapsed, start + elapsed].into_iter();
			let mut reads = 0;
			let mut writes = 0;
			let result = copy_with_cadence::<Infallible, Infallible>(
				length,
				&mut [0; 1],
				|_, bytes| {
					reads += 1;
					bytes.fill(7);
					Ok(())
				},
				|_, bytes, checkpoint| {
					writes += 1;
					assert_eq!(bytes, [7]);
					assert_eq!(checkpoint.is_some(), expected_checkpoint);
					Ok(())
				},
				BASELINE_CADENCE,
				|| ticks.next().unwrap(),
			)
			.unwrap();

			assert_eq!((reads, writes), (length, length));
			let expected = if length == 0 { &[][..] } else { &[7] };
			assert_eq!(result.as_bytes(), blake3::hash(expected).as_bytes());
		}
	}

	#[test]
	fn first_read_or_admission_error_stops_the_stream() {
		let start = Instant::now();
		let cadence = CheckpointCadence {
			bytes: 1,
			..BASELINE_CADENCE
		};
		let read_error = copy_with_cadence::<_, Infallible>(
			2,
			&mut [0; 1],
			|_, _| Err(io::ErrorKind::UnexpectedEof),
			|_, _, _| panic!("a failed read must not reach admission"),
			cadence,
			|| start,
		)
		.unwrap_err();
		assert!(matches!(
			read_error,
			CopyMeasureError::Read {
				offset: 0,
				source: io::ErrorKind::UnexpectedEof,
			}
		));

		let admission_error = copy_with_cadence::<Infallible, _>(
			2,
			&mut [0; 1],
			|offset, bytes| {
				assert_eq!(offset, 0, "no later read can follow failed admission");
				bytes.fill(7);
				Ok(())
			},
			|offset, bytes, checkpoint| {
				assert_eq!(offset, 0);
				assert_eq!(
					checkpoint,
					Some(RangeMeasurement {
						offset,
						length: 1,
						digest: ContentDigest(blake3::hash(bytes)),
					})
				);
				Err(io::ErrorKind::StorageFull)
			},
			cadence,
			|| start,
		)
		.unwrap_err();
		assert!(matches!(
			admission_error,
			CopyMeasureError::Write {
				offset: 0,
				source: io::ErrorKind::StorageFull,
			}
		));
	}

	#[test]
	fn invalid_input_stops_before_clock_or_callbacks() {
		let error = copy_with_cadence::<Infallible, Infallible>(
			1,
			&mut [],
			|_, _| panic!("invalid input must not reach the reader"),
			|_, _, _| panic!("invalid input must not reach admission"),
			BASELINE_CADENCE,
			|| panic!("invalid input must not initialize the clock"),
		)
		.unwrap_err();
		assert!(matches!(
			error,
			CopyMeasureError::InvalidInput(StreamInputError::EmptyScratch)
		));
	}
}
