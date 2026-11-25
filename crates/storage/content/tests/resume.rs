//! Positioned I/O and digest checks for historical checkpoint reuse.

use std::cell::RefCell;
use std::convert::Infallible;
use std::io;

use exacopy_content::{
	CheckpointCandidate, MAX_SCRATCH_BYTES, MeasureError, ResumeMeasureError, StreamInputError,
	resume_and_measure_at,
};
use exacopy_endpoint::MAX_FILE_LENGTH;

#[test]
fn writes_only_corrupt_stale_unavailable_and_uncheckpointed_ranges() {
	let history = b"abcdefghijklmnopqrst";
	let source = b"abcdefghixklmnopqrst";
	let stage = RefCell::new(b"abcde!ghijklmn".to_vec());
	let candidates = [0, 4, 8, 12].map(|offset| candidate(history, offset, 4));
	let mut source_reads = Vec::new();
	let mut stage_reads = Vec::new();
	let mut writes = Vec::new();
	let stage_length = stage.borrow().len() as u64;
	let measurement = resume_and_measure_at::<Infallible, Infallible, Infallible>(
		source.len() as u64,
		stage_length,
		&mut [0; 3],
		&candidates,
		|offset, bytes| {
			source_reads.push((offset, bytes.len()));
			read_at(source, offset, bytes);
			Ok(())
		},
		|offset, bytes| {
			stage_reads.push((offset, bytes.len()));
			read_at(&stage.borrow(), offset, bytes);
			Ok(())
		},
		|offset, bytes| {
			writes.push((offset, bytes.len()));
			let begin = offset as usize;
			let end = begin + bytes.len();
			let mut stage = stage.borrow_mut();
			if end > stage.len() {
				stage.resize(end, 0);
			}
			stage[begin..end].copy_from_slice(bytes);
			Ok(())
		},
	)
	.unwrap();

	assert_eq!(&*stage.borrow(), source);
	assert_eq!(
		measurement.digest.as_bytes(),
		blake3::hash(source).as_bytes()
	);
	assert_eq!(measurement.reused_bytes, 4);
	assert_eq!(
		stage_reads,
		[(0, 3), (3, 1), (4, 3), (7, 1), (8, 3), (11, 1)]
	);
	assert_eq!(
		source_reads,
		[
			(0, 3),
			(3, 1),
			(4, 3),
			(7, 1),
			(8, 3),
			(11, 1),
			(8, 3),
			(11, 1),
			(12, 3),
			(15, 1),
			(16, 3),
			(19, 1)
		]
	);
	assert_eq!(
		writes,
		[
			(4, 3),
			(7, 1),
			(8, 3),
			(11, 1),
			(12, 3),
			(15, 1),
			(16, 3),
			(19, 1)
		]
	);
}

#[test]
fn changed_source_during_rewrite_aborts_before_the_suffix() {
	let history = b"abcde";
	let mut read_offsets = Vec::new();
	let mut writes = Vec::new();
	let error = resume_and_measure_at::<Infallible, Infallible, Infallible>(
		5,
		5,
		&mut [0; 2],
		&[candidate(history, 0, 4)],
		|offset, bytes| {
			let source = if read_offsets.len() < 2 {
				b"zbcd"
			} else {
				b"zbcy"
			};
			read_at(source, offset, bytes);
			read_offsets.push(offset);
			Ok(())
		},
		|offset, bytes| {
			read_at(history, offset, bytes);
			Ok(())
		},
		|offset, bytes| {
			writes.push((offset, bytes.to_vec()));
			Ok(())
		},
	)
	.unwrap_err();
	assert!(matches!(
		error,
		ResumeMeasureError::SourceChanged {
			offset: 0,
			length: 4
		}
	));
	assert_eq!(read_offsets, [0, 2, 0, 2]);
	assert_eq!(writes, [(0, b"zb".to_vec()), (2, b"cy".to_vec())]);
}

#[test]
fn stage_read_failure_inside_its_extent_stops_before_source_or_write() {
	let range = candidate(b"abcd", 0, 4);
	let mut offsets = Vec::new();
	let error = resume_and_measure_at::<Infallible, _, Infallible>(
		4,
		4,
		&mut [0; 2],
		&[range],
		|_, _| panic!("source must not be read when the held stage failed"),
		|offset, bytes| {
			offsets.push(offset);
			if offset == 0 {
				bytes.copy_from_slice(b"ab");
				Ok(())
			} else {
				Err(io::ErrorKind::UnexpectedEof)
			}
		},
		|_, _| panic!("a held stage error must not fall back to a write"),
	)
	.unwrap_err();

	assert_eq!(offsets, [0, 2]);
	assert!(matches!(
		error,
		ResumeMeasureError::Stage(MeasureError::Read {
			offset: 2,
			source: io::ErrorKind::UnexpectedEof,
		})
	));
}

#[test]
fn source_read_failure_stops_before_write() {
	let mut offsets = Vec::new();
	let error = resume_and_measure_at::<_, Infallible, Infallible>(
		4,
		0,
		&mut [0; 2],
		&[candidate(b"abcd", 0, 4)],
		|offset, _| {
			offsets.push(offset);
			Err(io::ErrorKind::PermissionDenied)
		},
		|_, _| panic!("an unavailable candidate must not read from the stage"),
		|_, _| panic!("a failed source read must not write to the stage"),
	)
	.unwrap_err();

	assert_eq!(offsets, [0]);
	assert!(matches!(
		error,
		ResumeMeasureError::Source(MeasureError::Read {
			offset: 0,
			source: io::ErrorKind::PermissionDenied,
		})
	));
}

#[test]
fn first_failed_stage_write_stops_the_stream() {
	let mut read_offsets = Vec::new();
	let mut write_offsets = Vec::new();
	let error = resume_and_measure_at::<Infallible, Infallible, _>(
		4,
		0,
		&mut [0; 2],
		&[],
		|offset, bytes| {
			read_offsets.push(offset);
			read_at(b"abcd", offset, bytes);
			Ok(())
		},
		|_, _| panic!("a suffix without candidates must not read from the stage"),
		|offset, bytes| {
			write_offsets.push(offset);
			assert_eq!(bytes, b"ab");
			Err(io::ErrorKind::StorageFull)
		},
	)
	.unwrap_err();

	assert_eq!(read_offsets, [0]);
	assert_eq!(write_offsets, [0]);
	assert!(matches!(
		error,
		ResumeMeasureError::Write {
			offset: 0,
			source: io::ErrorKind::StorageFull,
		}
	));
}

#[test]
fn all_candidates_are_validated_before_any_io() {
	let first = candidate(b"abcd", 0, 2);
	for (offset, length) in [(2, 0), (1, 1), (3, 1), (2, 3), (2, u64::MAX)] {
		let invalid = CheckpointCandidate {
			offset,
			length,
			..first
		};
		let error = resume_and_measure_at::<Infallible, Infallible, Infallible>(
			4,
			4,
			&mut [0; 2],
			&[first, invalid],
			no_read,
			no_read,
			no_write,
		)
		.unwrap_err();
		assert!(matches!(
			error,
			ResumeMeasureError::InvalidCandidate { offset: actual_offset, length: actual_length }
				if actual_offset == offset && actual_length == length
		));
	}
}

#[test]
fn checks_stream_input_and_accepts_an_empty_source() {
	let oversized_scratch = MAX_SCRATCH_BYTES + 1;
	for (length, stage_length, scratch_len, expected) in [
		(1, 1, 0, StreamInputError::EmptyScratch),
		(
			1,
			1,
			oversized_scratch,
			StreamInputError::ScratchTooLarge {
				length: oversized_scratch,
			},
		),
		(
			MAX_FILE_LENGTH + 1,
			1,
			1,
			StreamInputError::FileTooLong {
				length: MAX_FILE_LENGTH + 1,
			},
		),
		(
			1,
			MAX_FILE_LENGTH + 1,
			1,
			StreamInputError::FileTooLong {
				length: MAX_FILE_LENGTH + 1,
			},
		),
	] {
		let error = resume_and_measure_at::<Infallible, Infallible, Infallible>(
			length,
			stage_length,
			&mut vec![0; scratch_len],
			&[],
			no_read,
			no_read,
			no_write,
		)
		.unwrap_err();
		assert!(matches!(error, ResumeMeasureError::InvalidInput(actual) if actual == expected));
	}
	let empty = resume_and_measure_at::<Infallible, Infallible, Infallible>(
		0,
		1,
		&mut [],
		&[],
		no_read,
		no_read,
		no_write,
	)
	.unwrap();
	assert_eq!(empty.digest.as_bytes(), blake3::hash(b"").as_bytes());
	assert_eq!(empty.reused_bytes, 0);
}

fn candidate(history: &[u8], begin: usize, length: usize) -> CheckpointCandidate {
	CheckpointCandidate {
		offset: begin as u64,
		length: length as u64,
		digest: *blake3::hash(&history[begin..begin + length]).as_bytes(),
	}
}

fn read_at(source: &[u8], offset: u64, bytes: &mut [u8]) {
	let begin = offset as usize;
	bytes.copy_from_slice(&source[begin..begin + bytes.len()]);
}

fn no_read(_: u64, _: &mut [u8]) -> Result<(), Infallible> {
	panic!("this input must not reach a read")
}

fn no_write(_: u64, _: &[u8]) -> Result<(), Infallible> {
	panic!("this input must not reach a write")
}
