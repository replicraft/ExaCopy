use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;

use apfs_mounted::dataless::PolicyError;
use apfs_mounted::writer::{BarrierError, BarrierKind, LifecycleEffect, WriterError};
use exacopy_endpoint::MAX_FILE_LENGTH;

use super::super::tests::{Fixture, make_stage, open_staging};
use super::{MAX_STAGE_IO_BYTES, StageError, bounded_end};

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
fn consecutive_mounted_writes_advance_exactly_to_the_declared_end() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let mut writer = make_stage(&directory, 6).unwrap();
	for byte in b"abcdef" {
		writer.write_next(std::slice::from_ref(byte)).unwrap();
	}
	let stage = writer.flush_and_close().unwrap();
	let mut read_back = [0; 6];
	let reader = stage.open_read_back().unwrap();
	reader.read_exact_at(0, &mut read_back).unwrap();
	reader.revalidate().unwrap();
	assert_eq!(read_back, *b"abcdef");
}

// Companion tests inject short syscalls and interruption retries. The façade
// sees the typed result of that entire call, never its writable descriptor.
#[test]
fn mounted_write_errors_retire_the_adapter_without_reusing_a_failed_range() {
	for kind in [
		io::ErrorKind::Interrupted,
		io::ErrorKind::WriteZero,
		io::ErrorKind::InvalidData,
	] {
		let fixture = Fixture::new();
		let root = fixture.bind();
		let directory = open_staging(&root);
		let mut writer = make_stage(&directory, 1).unwrap();
		let failure = writer.write_next_with(b"x", |_, _| Err(WriterError::Write(kind.into())));
		assert!(
			matches!(failure, Err(StageError::Mounted(WriterError::Write(error))) if error.kind() == kind)
		);
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
}

#[test]
fn a_failed_mounted_suffix_retains_a_written_prefix_and_retires_the_writer() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let mut writer = make_stage(&directory, 6).unwrap();
	let failure = writer.write_next_with(b"abcdef", |mounted, bytes| {
		mounted.write_next(&bytes[..2])?;
		Err(WriterError::Write(io::Error::from_raw_os_error(libc::EIO)))
	});
	assert!(
		matches!(failure, Err(StageError::Mounted(WriterError::Write(error))) if error.raw_os_error() == Some(libc::EIO))
	);
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
fn barrier_and_close_errors_keep_typed_boundaries_and_retain_bytes() {
	for failure_during_close in [false, true] {
		let fixture = Fixture::new();
		let root = fixture.bind();
		let directory = open_staging(&root);
		let mut writer = make_stage(&directory, 3).unwrap();
		writer.write_next(b"abc").unwrap();
		let error = writer
			.finish_with(|mounted| {
				let error = io::Error::from_raw_os_error(libc::EIO);
				if failure_during_close {
					drop(mounted.flush_and_close()?);
					Err(WriterError::Close(error))
				} else {
					Err(WriterError::Barrier(BarrierError {
						kind: BarrierKind::FullFile,
						error,
					}))
				}
			})
			.unwrap_err();
		if failure_during_close {
			assert!(
				matches!(error, StageError::CloseWriter(error) if error.raw_os_error() == Some(libc::EIO))
			);
		} else {
			assert!(
				matches!(error, StageError::FileBarrier(error) if error.raw_os_error() == Some(libc::EIO))
			);
		}
		assert_eq!(fs::read(fixture.stage_path()).unwrap(), b"abc");
	}
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
		.write_next_with(b"x", |_, _| Ok(()))
		.expect_err("no write was actually completed");
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

#[test]
fn mounted_effectful_failure_distinctions_survive_projection() {
	let after_create = StageError::from(WriterError::CreatedButUnverified(Box::new(
		WriterError::Changed,
	)));
	assert!(
		matches!(after_create, StageError::Mounted(WriterError::CreatedButUnverified(error)) if matches!(*error, WriterError::Changed))
	);
	let after_barrier = StageError::from(WriterError::BarrierPassedButUnverified(Box::new(
		WriterError::Changed,
	)));
	assert!(
		matches!(after_barrier, StageError::Mounted(WriterError::BarrierPassedButUnverified(error)) if matches!(*error, WriterError::Changed))
	);
	let after_close = StageError::from(WriterError::ClosedButUnverified(Box::new(
		WriterError::Changed,
	)));
	assert!(
		matches!(after_close, StageError::Mounted(WriterError::ClosedButUnverified(error)) if matches!(*error, WriterError::Changed))
	);
	let after_update = StageError::from(WriterError::TimesAppliedButUnverified(Box::new(
		WriterError::TimesMismatch,
	)));
	assert!(
		matches!(after_update, StageError::Mounted(WriterError::TimesAppliedButUnverified(error)) if matches!(*error, WriterError::TimesMismatch))
	);
	let restoration = StageError::from(WriterError::Restore {
		error: PolicyError::Io(io::ErrorKind::PermissionDenied.into()),
		outcome: Ok(LifecycleEffect::Closed),
	});
	assert!(matches!(
		restoration,
		StageError::Mounted(WriterError::Restore {
			outcome: Ok(LifecycleEffect::Closed),
			..
		})
	));
}

#[test]
fn closed_mounted_stage_with_rebound_name_retains_both_entries() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let mut writer = make_stage(&directory, 3).unwrap();
	writer.write_next(b"abc").unwrap();
	let path = fixture.stage_path();
	let retained = fixture.path("retained-closed-stage");
	let original = writer.observe_identity().unwrap();
	let failure = writer
		.finish_with(|mounted| {
			let closed = mounted.flush_and_close()?;
			fs::rename(&path, &retained)?;
			fs::write(&path, b"incumbent")?;
			Ok(closed)
		})
		.unwrap_err();
	assert!(
		matches!(failure, StageError::ClosedUnverified(cause) if matches!(*cause, StageError::StageChanged))
	);
	assert_eq!(
		fs::metadata(&retained).unwrap().ino(),
		original.inode().get()
	);
	assert_eq!(fs::read(&retained).unwrap(), b"abc");
	assert_eq!(fs::read(&path).unwrap(), b"incumbent");
	assert!(!fixture.path("target").exists());
}

#[test]
fn present_no_acl_marker_is_refused_before_mounted_write() {
	use apfs_mounted::metadata::{
		ExtendedSecurity, MAX_EXTENDED_SECURITY_BYTES, extended_security,
	};

	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let mut writer = make_stage(&directory, 1).unwrap();
	let original = writer.observe_identity().unwrap();
	let ExtendedSecurity::Present(mut payload) =
		extended_security(directory.mounted_stage(), MAX_EXTENDED_SECURITY_BYTES).unwrap()
	else {
		panic!("provisioned APFS fixture must return its explicit empty ACL");
	};
	assert_eq!(payload.entry_count, Some(0));
	assert_eq!(payload.flags, 0);
	// The pinned parser uses None for Darwin's FILESEC_NOACL marker.
	// Feed that exact typed observation through the same pre-write predicate.
	payload.entry_count = None;
	let observed = ExtendedSecurity::Present(payload);
	assert!(
		observed.has_no_acl_entries(),
		"companion intentionally accepts this variant"
	);
	let error = writer
		.write_next_with_security(
			b"x",
			|_| Ok(observed.clone()),
			|_, _| panic!("an ineligible present ACL must stop before the write call"),
		)
		.unwrap_err();
	assert!(matches!(error, StageError::StageChanged));
	assert!(matches!(
		writer.flush_and_close(),
		Err(StageError::WriterRetired)
	));
	let retained = fs::metadata(fixture.stage_path()).unwrap();
	assert_eq!(retained.ino(), original.inode().get());
	assert_eq!(retained.len(), 0);
	assert!(!fixture.path("target").exists());
}
