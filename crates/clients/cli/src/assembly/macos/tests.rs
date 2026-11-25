use std::fs;
use std::process::Command;

use exacopy_content::{CopyMeasureError, StreamInputError, measure_at};
use exacopy_platform::macos::staging::{MAX_STAGE_IO_BYTES, StageError};
use exacopy_platform::macos::{BasicMetadataError, ManagedReadError};

use exacopy_transfer::staging::verify_read_back;

use super::{StageTransferFailure, copy_verified_stage, copy_with_basic_metadata};

mod fixture;

use fixture::{Fixture, ORIGINAL, PAYLOAD, SOURCE, TARGET, write_file};

#[test]
fn strict_copy_refuses_visible_attributes_before_writing_the_stage() {
	let fixture = Fixture::new();
	let source = fixture.destination.join(SOURCE);
	write_file(&source, PAYLOAD);
	let status = Command::new("/usr/bin/xattr")
		.args(["-w", "com.example.exacopy-test", "fixture"])
		.arg(&source)
		.status()
		.expect("set a synthetic visible attribute");
	assert!(status.success());
	let root = fixture.stage_root();
	let source = fixture.same_parent_source(&root);
	let directory = fixture.stage_directory(&root);
	let writer = fixture.writer(&directory, source.length());
	let identity = writer.identity();
	let error = copy_with_basic_metadata(&source, writer, &mut [0; 8])
		.expect_err("refuse a source with visible attributes");
	assert_eq!(error.identity(), identity);
	assert!(matches!(
		error.failure(),
		StageTransferFailure::AdmitMetadata(ManagedReadError::BasicMetadata(
			BasicMetadataError::ExtendedAttributes
		))
	));
	assert!(fs::read(&fixture.stage).unwrap().is_empty());
	fixture.assert_target_absent();
}

#[test]
fn verifies_multiple_chunks_from_the_same_parent_lease() {
	let fixture = Fixture::new();
	write_file(&fixture.destination.join(SOURCE), PAYLOAD);
	let root = fixture.stage_root();
	let source = fixture.same_parent_source(&root);
	let directory = fixture.stage_directory(&root);
	let writer = fixture.writer(&directory, source.length());
	let identity = writer.identity();
	write_file(&fixture.destination.join(TARGET), ORIGINAL);

	let verified = copy_verified_stage(&source, writer, &mut [0; 7]).unwrap();

	assert_eq!(verified.identity(), identity);
	assert_eq!(verified.binding(), identity.binding());
	assert_eq!(verified.length(), source.length());
	assert!(!verified.is_empty());
	assert_eq!(
		verified.digest().as_bytes(),
		blake3::hash(PAYLOAD).as_bytes()
	);
	assert_eq!(fs::read(&fixture.stage).unwrap(), PAYLOAD);
	assert_eq!(fs::read(fixture.destination.join(SOURCE)).unwrap(), PAYLOAD);
	assert_eq!(
		fs::read(fixture.destination.join(TARGET)).unwrap(),
		ORIGINAL
	);
}

#[test]
fn verifies_an_independent_source_with_the_maximum_stage_chunk() {
	let fixture = Fixture::new();
	let mut payload = vec![b'x'; MAX_STAGE_IO_BYTES];
	payload.extend_from_slice(PAYLOAD);
	write_file(&fixture.independent.join(SOURCE), &payload);
	let read_root = fixture.read_root();
	let source = fixture.independent_source(&read_root);
	let root = fixture.stage_root();
	let directory = fixture.stage_directory(&root);
	let writer = fixture.writer(&directory, source.length());

	let verified = copy_verified_stage(&source, writer, &mut vec![0; MAX_STAGE_IO_BYTES]).unwrap();

	assert_eq!(
		verified.digest().as_bytes(),
		blake3::hash(&payload).as_bytes()
	);
	assert_eq!(fs::read(&fixture.stage).unwrap(), payload);
	assert_eq!(fs::read(fixture.independent.join(SOURCE)).unwrap(), payload);
	fixture.assert_target_absent();
}

#[test]
fn verifies_empty_source_with_empty_scratch() {
	let fixture = Fixture::new();
	write_file(&fixture.destination.join(SOURCE), b"");
	let root = fixture.stage_root();
	let source = fixture.same_parent_source(&root);
	let directory = fixture.stage_directory(&root);
	let writer = fixture.writer(&directory, 0);

	let verified = copy_verified_stage(&source, writer, &mut []).unwrap();

	assert!(verified.is_empty());
	assert_eq!(verified.digest().as_bytes(), blake3::hash(b"").as_bytes());
	assert_eq!(fs::read(&fixture.stage).unwrap(), b"");
	fixture.assert_target_absent();
}

#[test]
fn refuses_different_extents_before_writing() {
	use StageTransferFailure::ExtentMismatch;

	let fixture = Fixture::new();
	write_file(&fixture.destination.join(SOURCE), PAYLOAD);
	let root = fixture.stage_root();
	let source = fixture.same_parent_source(&root);
	let directory = fixture.stage_directory(&root);
	let writer = fixture.writer(&directory, source.length() + 1);
	let identity = writer.identity();

	let error = copy_verified_stage(&source, writer, &mut [0; 7]).unwrap_err();

	assert_eq!(error.identity(), identity);
	assert!(matches!(
		error.failure(),
		ExtentMismatch { source_length, stage_length }
			if *source_length == source.length() && *stage_length == source.length() + 1
	));
	assert_eq!(fs::read(&fixture.stage).unwrap(), b"");
	assert_eq!(fs::read(fixture.destination.join(SOURCE)).unwrap(), PAYLOAD);
	fixture.assert_target_absent();
}

#[test]
fn refuses_scratch_above_the_stage_limit_or_empty_for_nonempty_source() {
	for scratch_size in [0, MAX_STAGE_IO_BYTES + 1] {
		let fixture = Fixture::new();
		write_file(&fixture.destination.join(SOURCE), PAYLOAD);
		let root = fixture.stage_root();
		let source = fixture.same_parent_source(&root);
		let directory = fixture.stage_directory(&root);
		let writer = fixture.writer(&directory, source.length());
		let identity = writer.identity();

		let error = copy_verified_stage(&source, writer, &mut vec![0; scratch_size]).unwrap_err();

		assert_eq!(error.identity(), identity);
		match error.failure() {
			StageTransferFailure::InvalidInput(StreamInputError::EmptyScratch) => {
				assert_eq!(scratch_size, 0);
			}
			StageTransferFailure::ScratchTooLarge { length } => {
				assert_eq!(*length, MAX_STAGE_IO_BYTES + 1);
				assert_eq!(*length, scratch_size);
			}
			failure => panic!("unexpected failure for {scratch_size} bytes: {failure:?}"),
		}
		assert_eq!(fs::read(&fixture.stage).unwrap(), b"");
		assert_eq!(fs::read(fixture.destination.join(SOURCE)).unwrap(), PAYLOAD);
		fixture.assert_target_absent();
	}
}

#[test]
fn refuses_a_started_writer_and_preserves_its_prefix() {
	let fixture = Fixture::new();
	write_file(&fixture.destination.join(SOURCE), PAYLOAD);
	let root = fixture.stage_root();
	let source = fixture.same_parent_source(&root);
	let directory = fixture.stage_directory(&root);
	let mut writer = fixture.writer(&directory, source.length());
	let identity = writer.identity();
	writer.write_next(b"old").unwrap();

	let error = copy_verified_stage(&source, writer, &mut [0; 7]).unwrap_err();

	assert_eq!(error.identity(), identity);
	assert!(matches!(
		error.failure(),
		StageTransferFailure::InitialStage(StageError::AlreadyWritten)
	));
	assert_eq!(fs::read(&fixture.stage).unwrap(), b"old");
	assert_eq!(fs::read(fixture.destination.join(SOURCE)).unwrap(), PAYLOAD);
	fixture.assert_target_absent();
}

#[test]
fn stale_source_identity_prevents_writing() {
	let fixture = Fixture::new();
	let name = fixture.destination.join(SOURCE);
	let original = fixture.destination.join("held-source");
	write_file(&name, PAYLOAD);
	let root = fixture.stage_root();
	let source = fixture.same_parent_source(&root);
	let directory = fixture.stage_directory(&root);
	let writer = fixture.writer(&directory, source.length());
	let identity = writer.identity();
	fs::rename(&name, &original).unwrap();
	write_file(&name, PAYLOAD);

	let error = copy_verified_stage(&source, writer, &mut [0; 7]).unwrap_err();

	assert_eq!(error.identity(), identity);
	assert!(matches!(
		error.failure(),
		StageTransferFailure::RevalidateSource(ManagedReadError::SourceChanged)
	));
	assert_eq!(fs::read(&fixture.stage).unwrap(), b"");
	assert_eq!(fs::read(&name).unwrap(), PAYLOAD);
	assert_eq!(fs::read(&original).unwrap(), PAYLOAD);
	fixture.assert_target_absent();
}

#[test]
fn changed_stage_name_fails_write_without_touching_either_entry() {
	let fixture = Fixture::new();
	write_file(&fixture.destination.join(SOURCE), PAYLOAD);
	let root = fixture.stage_root();
	let source = fixture.same_parent_source(&root);
	let directory = fixture.stage_directory(&root);
	let writer = fixture.writer(&directory, source.length());
	let identity = writer.identity();
	let original_stage = fixture.stage.with_file_name("held-stage");
	fs::rename(&fixture.stage, &original_stage).unwrap();
	write_file(&fixture.stage, ORIGINAL);

	let error = copy_verified_stage(&source, writer, &mut [0; 7]).unwrap_err();

	assert_eq!(error.identity(), identity);
	assert!(matches!(
		error.failure(),
		StageTransferFailure::Copy(CopyMeasureError::Write {
			offset: 0,
			source: StageError::StageChanged,
		})
	));
	assert_eq!(fs::read(&original_stage).unwrap(), b"");
	assert_eq!(fs::read(&fixture.stage).unwrap(), ORIGINAL);
	assert_eq!(fs::read(fixture.destination.join(SOURCE)).unwrap(), PAYLOAD);
	fixture.assert_target_absent();
}

#[test]
fn read_back_checks_digest_and_refuses_a_rebound_closed_stage() {
	let fixture = Fixture::new();
	let root = fixture.stage_root();
	let directory = fixture.stage_directory(&root);
	let mut writer = fixture.writer(&directory, 3);
	writer.write_next(b"old").unwrap();
	let closed = writer.flush_and_close().unwrap();
	let wrong_digest = measure_at(3, &mut [0; 3], |_, output| {
		output.copy_from_slice(b"new");
		Ok::<_, StageError>(())
	})
	.unwrap();

	let error = verify_read_back::<ManagedReadError, _>(
		&closed,
		closed.length(),
		wrong_digest,
		&mut [0; 2],
	)
	.map_err(StageTransferFailure::from_copy)
	.unwrap_err();

	assert!(matches!(
		error,
		StageTransferFailure::DigestMismatch { source_digest, stage_digest }
			if source_digest == wrong_digest && stage_digest.as_bytes() == blake3::hash(b"old").as_bytes()
	));
	assert_eq!(fs::read(&fixture.stage).unwrap(), b"old");

	let original_stage = fixture.stage.with_file_name("held-stage");
	fs::rename(&fixture.stage, &original_stage).unwrap();
	write_file(&fixture.stage, b"old");
	let error = verify_read_back::<ManagedReadError, _>(
		&closed,
		closed.length(),
		wrong_digest,
		&mut [0; 2],
	)
	.map_err(StageTransferFailure::from_copy)
	.unwrap_err();

	assert!(matches!(
		error,
		StageTransferFailure::OpenReadBack(StageError::StageChanged)
	));
	assert_eq!(fs::read(&original_stage).unwrap(), b"old");
	assert_eq!(fs::read(&fixture.stage).unwrap(), b"old");
	fixture.assert_target_absent();
}
