use std::cell::Cell;
use std::fs;
use std::io;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};

use exacopy_endpoint::{IoError, MAX_FILE_LENGTH, MAX_INTERRUPTED_RETRIES};
use rustix::io::Errno;

use super::super::tests::{Fixture, make_stage, open_staging};
use super::{MAX_STAGE_IO_BYTES, StageError, bounded_end, close_writer};

#[test]
fn bounds_reject_chunk_overflow_and_range_past_the_declared_extent() {
	assert_eq!(
		bounded_end(0, MAX_STAGE_IO_BYTES, MAX_FILE_LENGTH).unwrap(),
		MAX_STAGE_IO_BYTES as u64
	);
	assert_eq!(
		bounded_end(MAX_FILE_LENGTH - 1, 1, MAX_FILE_LENGTH).unwrap(),
		MAX_FILE_LENGTH
	);
	assert_eq!(
		bounded_end(MAX_FILE_LENGTH, 0, MAX_FILE_LENGTH).unwrap(),
		MAX_FILE_LENGTH
	);
	for (offset, size) in [
		(0, MAX_STAGE_IO_BYTES + 1),
		(MAX_FILE_LENGTH, 1),
		(MAX_FILE_LENGTH + 1, 0),
		(u64::MAX, 1),
		(1, usize::MAX),
	] {
		assert!(matches!(
			bounded_end(offset, size, MAX_FILE_LENGTH),
			Err(StageError::InvalidRange)
		));
	}
}

#[test]
fn successful_short_write_retries_only_the_remaining_suffix_at_its_position() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let mut writer = make_stage(&directory, 6).unwrap();
	let mut calls = 0;
	writer
		.write_next_with(b"abcdef", |file, offset, bytes| {
			calls += 1;
			assert_eq!(offset, u64::try_from(calls - 1).unwrap());
			assert_eq!(bytes, &b"abcdef"[calls - 1..]);
			file.write_at(&bytes[..1], offset)
		})
		.unwrap();
	assert_eq!(calls, 6);
	let stage = writer.flush_and_close().unwrap();
	let mut read_back = [0; 6];
	stage
		.open_read_back()
		.unwrap()
		.read_exact_at(0, &mut read_back)
		.unwrap();
	assert_eq!(read_back, *b"abcdef");
}

#[test]
fn exhausted_interruptions_retire_without_transferring_or_retrying_later() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let mut writer = make_stage(&directory, 1).unwrap();
	let mut calls = 0;
	let failure = writer.write_next_with(b"x", |_file, offset, bytes| {
		assert_eq!((offset, bytes), (0, b"x".as_slice()));
		calls += 1;
		Err(io::ErrorKind::Interrupted.into())
	});
	assert_eq!(calls, MAX_INTERRUPTED_RETRIES + 1);
	assert!(matches!(
		failure,
		Err(StageError::Write(IoError::System { offset: 0, source }))
			if source.kind() == io::ErrorKind::Interrupted
	));
	assert!(matches!(
		writer.write_next(b"x"),
		Err(StageError::WriterRetired)
	));
	assert!(matches!(
		writer.flush_and_close(),
		Err(StageError::WriterRetired)
	));
	assert_eq!(fs::metadata(fixture.stage_path()).unwrap().len(), 0);
}

#[test]
fn a_failed_suffix_retains_a_written_prefix_and_retires_the_writer() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let mut writer = make_stage(&directory, 6).unwrap();
	let failure = writer.write_next_with(b"abcdef", |file, offset, bytes| match offset {
		0 => file.write_at(&bytes[..2], offset),
		2 => {
			assert_eq!(bytes, b"cdef");
			Err(io::Error::from_raw_os_error(libc::EIO))
		}
		_ => panic!("unexpected offset {offset}"),
	});
	assert!(matches!(
		failure,
		Err(StageError::Write(IoError::System { offset: 2, source }))
			if source.raw_os_error() == Some(libc::EIO)
	));
	assert!(matches!(
		writer.write_next(b"abcdef"),
		Err(StageError::WriterRetired)
	));
	assert!(matches!(
		writer.flush_and_close(),
		Err(StageError::WriterRetired)
	));
	assert_eq!(fs::read(fixture.stage_path()).unwrap(), b"ab");
}

#[test]
fn zero_progress_and_impossible_counts_permanently_reject_the_writer() {
	for count in [0, 2] {
		let fixture = Fixture::new();
		let root = fixture.bind();
		let directory = open_staging(&root);
		let mut writer = make_stage(&directory, 1).unwrap();
		let error = writer
			.write_next_with(b"x", |_, _, _| Ok(count))
			.unwrap_err();
		match count {
			0 => assert!(matches!(
				error,
				StageError::Write(IoError::WriteZero { offset: 0 })
			)),
			_ => assert!(matches!(
				error,
				StageError::Write(IoError::InvalidTransferCount {
					offset: 0,
					count: 2,
					remaining: 1
				})
			)),
		}
		assert!(matches!(
			writer.write_next(b"x"),
			Err(StageError::WriterRetired)
		));
		assert_eq!(fs::metadata(fixture.stage_path()).unwrap().len(), 0);
	}
}

#[test]
fn barrier_failure_retains_exact_bytes_without_issuing_a_closed_stage() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let mut writer = make_stage(&directory, 3).unwrap();
	writer.write_next(b"abc").unwrap();
	let error = writer
		.finish_with(
			|_| Err(Errno::IO),
			|_| panic!("a failed barrier must precede closure evidence"),
		)
		.unwrap_err();
	assert!(
		matches!(error, StageError::FileBarrier(source) if source.raw_os_error() == Some(libc::EIO))
	);
	assert_eq!(fs::read(fixture.stage_path()).unwrap(), b"abc");
}

#[test]
fn close_error_after_successful_barrier_blocks_closed_stage() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let mut writer = make_stage(&directory, 3).unwrap();
	writer.write_next(b"abc").unwrap();
	let barrier = Cell::new(false);
	let error = writer
		.finish_with(
			|file| {
				rustix::fs::fcntl_fullfsync(file)?;
				barrier.set(true);
				Ok(())
			},
			|file| {
				assert!(barrier.get(), "close must follow barrier success");
				close_writer(file)?;
				Err(StageError::CloseWriter(io::Error::from_raw_os_error(
					libc::EIO,
				)))
			},
		)
		.unwrap_err();
	assert!(
		matches!(error, StageError::CloseWriter(source) if source.raw_os_error() == Some(libc::EIO))
	);
	assert_eq!(fs::read(fixture.stage_path()).unwrap(), b"abc");
}

#[test]
fn hard_link_added_to_private_file_before_write_retires_without_touching_either_name() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let mut writer = make_stage(&directory, 1).unwrap();
	let alias = fixture.path("late-private-alias");
	fs::hard_link(fixture.stage_path(), &alias).unwrap();
	assert!(matches!(
		writer.write_next(b"x"),
		Err(StageError::StageChanged)
	));
	assert!(matches!(
		writer.write_next(b"x"),
		Err(StageError::WriterRetired)
	));
	assert_eq!(fs::metadata(alias).unwrap().len(), 0);
	assert_eq!(fs::metadata(fixture.stage_path()).unwrap().len(), 0);
}

#[test]
fn wrong_length_after_reported_write_retires_writer_and_retains_stage() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let mut writer = make_stage(&directory, 1).expect("create a one-byte stage");
	let original = writer.observe_identity().expect("hold the private inode");

	let error = writer
		.write_next_with(b"x", |file, offset, bytes| {
			assert_eq!(offset, 0);
			// Simulate a write implementation reporting success without writing.
			assert_eq!(file.metadata()?.len(), 0);
			Ok(bytes.len())
		})
		.expect_err("a transfer count cannot stand in for the actual inode extent");

	assert!(matches!(error, StageError::StageChanged));
	assert!(matches!(
		writer.unwritten_length(),
		Err(StageError::WriterRetired)
	));
	assert!(matches!(
		writer.flush_and_close(),
		Err(StageError::WriterRetired)
	));
	let retained = fs::metadata(fixture.stage_path()).expect("retain the original inode");
	assert_eq!(retained.ino(), original.inode().get());
	assert_eq!(retained.len(), 0);
	assert!(!fixture.path("target").exists());
}
