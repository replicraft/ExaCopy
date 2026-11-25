//! Standard digest vectors and bounded positioned transfer behavior.

use std::convert::Infallible;
use std::error::Error as _;
use std::io;

use exacopy_content::{
	CopyMeasureError, MAX_SCRATCH_BYTES, MeasureError, StreamInputError, copy_and_measure_at,
	measure_at, validate_stream_input,
};
use exacopy_endpoint::MAX_FILE_LENGTH;

// First 32 bytes of the canonical BLAKE3 outputs for the publisher's inputs.
// https://github.com/BLAKE3-team/BLAKE3/blob/1.8.7/test_vectors/test_vectors.json
const EMPTY_BLAKE3: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
const BLAKE3_1025_BYTES: &str = "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444";
const VECTOR_LENGTH: u64 = 1_025;
const VECTOR_LAST_BYTE: u8 = 250;

fn read_bytes(offset: u64, destination: &mut [u8], input: &[u8]) -> Result<(), Infallible> {
	let start = usize::try_from(offset).expect("fixture offsets fit in memory");
	destination.copy_from_slice(&input[start..][..destination.len()]);
	Ok(())
}

#[test]
fn empty_stream_has_the_standard_digest_without_callbacks() {
	let measurement =
		measure_at::<Infallible>(0, &mut [], |_, _| panic!("empty input requires no reads"))
			.expect("measure an empty stream");
	let copied = copy_and_measure_at::<Infallible, Infallible>(
		0,
		&mut [],
		|_, _| panic!("empty input requires no reads"),
		|_, _| panic!("empty input requires no writes"),
	)
	.expect("copy an empty stream");
	assert_eq!(measurement.to_string(), EMPTY_BLAKE3);
	assert_eq!(copied.as_bytes(), measurement.as_bytes());
}

#[test]
fn scratch_boundaries_do_not_change_the_standard_whole_stream_digest() {
	let length = usize::try_from(VECTOR_LENGTH).expect("vector fits in memory");
	let input: Vec<_> = (0..=VECTOR_LAST_BYTE).cycle().take(length).collect();
	for chunk_size in [1, 63, 64, 257, 1_024, 2_049] {
		let mut scratch = vec![0; chunk_size];
		let mut next_input_offset = 0;
		let digest = measure_at(VECTOR_LENGTH, &mut scratch, |offset, chunk| {
			assert_eq!(offset, next_input_offset);
			assert!(!chunk.is_empty());
			assert!(chunk.len() <= chunk_size);
			next_input_offset += u64::try_from(chunk.len()).expect("vector chunk fits in u64");
			read_bytes(offset, chunk, &input)
		})
		.expect("measure the publisher's test vector");
		assert_eq!(next_input_offset, VECTOR_LENGTH);
		assert_eq!(
			digest.to_string(),
			BLAKE3_1025_BYTES,
			"scratch size {chunk_size}"
		);
	}
}

#[test]
fn copies_logical_zero_bytes_and_detects_same_length_readback_changes() {
	let input = *b"head\0\0\0\0\0\0\0\0tail";
	let length = u64::try_from(input.len()).expect("fixture length fits in u64");
	let mut stage = [u8::MAX; 16];
	let mut writes = Vec::new();
	let source = copy_and_measure_at(
		length,
		&mut [u8::MAX; 5],
		|offset, chunk| read_bytes(offset, chunk, &input),
		|offset, chunk| {
			let start = usize::try_from(offset).expect("stage offset fits in memory");
			stage[start..][..chunk.len()].copy_from_slice(chunk);
			writes.push((offset, chunk.len()));
			Ok::<(), Infallible>(())
		},
	)
	.expect("copy the logical stream");
	assert_eq!(writes, [(0, 5), (5, 5), (10, 5), (15, 1)]);
	assert_eq!(stage, input);
	assert_eq!(source.as_bytes(), blake3::hash(&input).as_bytes());
	let readback = measure_at(length, &mut [0; 7], |offset, chunk| {
		read_bytes(offset, chunk, &stage)
	})
	.expect("independently measure the stage");
	assert_eq!(source, readback);
	stage[5] = 1;
	let changed = measure_at(length, &mut [0; 4], |offset, chunk| {
		read_bytes(offset, chunk, &stage)
	})
	.expect("measure changed bytes");
	assert_ne!(source, changed);
}

#[test]
fn invalid_limits_stop_before_reading_or_writing() {
	assert_eq!(MAX_SCRATCH_BYTES, 4_194_304);
	assert_eq!(validate_stream_input(0, 0), Ok(()));
	assert_eq!(
		validate_stream_input(1, 0),
		Err(StreamInputError::EmptyScratch)
	);
	let oversize = MAX_SCRATCH_BYTES + 1;
	assert_eq!(
		validate_stream_input(1, oversize),
		Err(StreamInputError::ScratchTooLarge { length: oversize })
	);
	let error = measure_at::<Infallible>(1, &mut vec![0; oversize], |_, _| {
		panic!("invalid scratch must be rejected before reading")
	})
	.expect_err("reject oversized scratch");
	assert!(matches!(
		error,
		MeasureError::InvalidInput(StreamInputError::ScratchTooLarge { length }) if length == oversize
	));
	assert!(
		error
			.to_string()
			.contains(&format!("scratch length {oversize}"))
	);
	assert_eq!(
		error
			.source()
			.and_then(|cause| cause.downcast_ref::<StreamInputError>()),
		Some(&StreamInputError::ScratchTooLarge { length: oversize })
	);
	let error = copy_and_measure_at::<Infallible, Infallible>(
		1,
		&mut [],
		|_, _| panic!("invalid scratch must be rejected before reading"),
		|_, _| panic!("invalid scratch must be rejected before writing"),
	)
	.expect_err("reject empty scratch for nonempty copy");
	assert!(matches!(
		error,
		CopyMeasureError::InvalidInput(StreamInputError::EmptyScratch)
	));
	assert_eq!(error.to_string(), "nonempty streams require scratch space");
	let excessive_length = MAX_FILE_LENGTH + 1;
	assert_eq!(
		validate_stream_input(excessive_length, 1),
		Err(StreamInputError::FileTooLong {
			length: excessive_length
		})
	);
	let error = copy_and_measure_at::<Infallible, Infallible>(
		excessive_length,
		&mut [0],
		|_, _| panic!("invalid file length must be rejected before reading"),
		|_, _| panic!("invalid file length must be rejected before writing"),
	)
	.expect_err("reject an extent beyond the endpoint limit");
	assert!(matches!(
		error,
		CopyMeasureError::InvalidInput(StreamInputError::FileTooLong { length }) if length == excessive_length
	));
	assert!(
		error
			.to_string()
			.contains(&format!("stream length {excessive_length}"))
	);
	assert_eq!(
		error
			.source()
			.and_then(|cause| cause.downcast_ref::<StreamInputError>()),
		Some(&StreamInputError::FileTooLong {
			length: excessive_length
		})
	);
}

#[test]
fn largest_extent_and_buffer_can_start_a_bounded_read() {
	let error = measure_at(
		MAX_FILE_LENGTH,
		&mut vec![0; MAX_SCRATCH_BYTES],
		|offset, chunk| {
			assert_eq!(offset, 0);
			assert_eq!(chunk.len(), MAX_SCRATCH_BYTES);
			Err(io::Error::from(io::ErrorKind::UnexpectedEof))
		},
	)
	.expect_err("backend could not supply the first chunk");
	assert!(matches!(
		&error,
		MeasureError::Read { offset: 0, source } if source.kind() == io::ErrorKind::UnexpectedEof
	));
	assert!(error.to_string().contains("stream read at 0 failed"));
	assert_eq!(
		error
			.source()
			.and_then(|source| source.downcast_ref::<io::Error>())
			.map(io::Error::kind),
		Some(io::ErrorKind::UnexpectedEof)
	);
}

#[test]
fn failed_source_read_does_not_write_its_partial_bytes() {
	let mut reads = Vec::new();
	let mut written = Vec::new();
	let error = copy_and_measure_at(
		8,
		&mut [0; 3],
		|offset, chunk| {
			reads.push(offset);
			if offset == 0 {
				chunk.copy_from_slice(b"abc");
				Ok(())
			} else {
				chunk[0] = b'd';
				Err(io::Error::from(io::ErrorKind::UnexpectedEof))
			}
		},
		|offset, chunk| {
			written.push((offset, chunk.to_vec()));
			Ok::<(), Infallible>(())
		},
	)
	.expect_err("failed read cannot produce a digest");
	assert!(matches!(
		&error,
		CopyMeasureError::Read { offset: 3, source } if source.kind() == io::ErrorKind::UnexpectedEof
	));
	assert!(error.to_string().contains("source read at 3 failed"));
	assert_eq!(
		error
			.source()
			.and_then(|source| source.downcast_ref::<io::Error>())
			.map(io::Error::kind),
		Some(io::ErrorKind::UnexpectedEof)
	);
	assert_eq!(reads, [0, 3]);
	assert_eq!(written, [(0, b"abc".to_vec())]);
}

#[test]
fn failed_stage_write_stops_without_reading_a_later_range() {
	const BACKEND_CODE: i32 = 28;
	let mut reads = Vec::new();
	let mut writes = Vec::new();
	let mut stage_prefix = Vec::new();
	let error = copy_and_measure_at(
		9,
		&mut [0; 3],
		|offset, chunk| {
			reads.push(offset);
			read_bytes(offset, chunk, b"abcdefghi")
		},
		|offset, chunk| {
			writes.push(offset);
			if offset == 0 {
				stage_prefix.extend_from_slice(chunk);
				Ok(())
			} else {
				stage_prefix.push(chunk[0]);
				Err(io::Error::from_raw_os_error(BACKEND_CODE))
			}
		},
	)
	.expect_err("failed write cannot produce a digest");
	assert!(matches!(
		&error,
		CopyMeasureError::Write { offset: 3, source } if source.raw_os_error() == Some(BACKEND_CODE)
	));
	assert!(error.to_string().contains("stage write at 3 failed"));
	assert_eq!(
		error
			.source()
			.and_then(|source| source.downcast_ref::<io::Error>())
			.and_then(io::Error::raw_os_error),
		Some(BACKEND_CODE)
	);
	assert_eq!(reads, [0, 3]);
	assert_eq!(writes, [0, 3]);
	assert_eq!(stage_prefix, b"abcd");
}
