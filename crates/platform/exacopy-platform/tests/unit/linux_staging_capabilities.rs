use std::fs::{self, Permissions};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use exacopy_model::{EntryId, JobId, RunEpoch, StageId};

use super::{
	CopyBinding, ExtendedAttributes, IoError, SourceMetadata, StageError, StageReader, StageWriter,
	StagingDirectory, StagingSource, UnixComponent,
};
use crate::linux::{DestinationRoot, ReadRoot};
use crate::scratch::Scratch;

const SOURCE: &str = "source";
const DIRECTORY: &str = "staging";
const PART: &str = "part";
const TARGET: &str = "target";
const PAYLOAD: &[u8] = b"private copy payload";
const SOURCE_MODE: u32 = 0o640;

#[test]
fn native_staging_capabilities_preserve_owned_bytes_and_refuse_existing_private_name() {
	let scratch = Scratch::new();
	let source_path = scratch.path(SOURCE);
	let target_path = scratch.path(TARGET);
	let part_path = scratch.path(DIRECTORY).join(PART);
	fs::write(&source_path, PAYLOAD).unwrap();
	fs::set_permissions(&source_path, Permissions::from_mode(SOURCE_MODE)).unwrap();
	fs::write(&target_path, b"incumbent").unwrap();
	let source_before = snapshot(&source_path);
	let incumbent_before = snapshot(&target_path);
	let source_root = ReadRoot::from_directory(scratch.open()).unwrap();
	let source = source_root.open_regular(component(SOURCE)).unwrap();
	let metadata = StagingSource::metadata(&source);
	assert_eq!(SourceMetadata::mode(metadata), SOURCE_MODE);
	assert_eq!(
		StagingSource::extended_attributes(&source).unwrap(),
		ExtendedAttributes::NoneVisible
	);
	let accessed = SourceMetadata::accessed_at(metadata);
	let mut payload = [0; PAYLOAD.len()];
	source.read_exact_at(0, &mut payload).unwrap();
	StagingSource::recheck_metadata(&source).unwrap();
	assert_eq!(payload, PAYLOAD);

	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let directory = root.create_stage_directory(component(DIRECTORY)).unwrap();
	let binding = CopyBinding::new(
		JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]).unwrap(),
		EntryId::new(1),
		RunEpoch::new(1),
		StageId::from_bytes([0x73; 16]),
	);
	let mut writer =
		StagingDirectory::create_file(&directory, component(PART), component(TARGET), binding)
			.unwrap();
	let identity = StageWriter::identity(&writer);
	assert_ne!(identity, StagingSource::identity(&source));
	StageWriter::check_ownership(&writer, metadata).unwrap();
	StageWriter::write_all_at(&mut writer, 0, &payload).unwrap();
	let extent = u64::try_from(payload.len()).unwrap();
	StageWriter::set_len(&mut writer, extent).unwrap();
	StageWriter::flush(&mut writer).unwrap();
	StagingDirectory::sync_directory(&directory).unwrap();

	let part_before = snapshot(&part_path);
	assert!(matches!(
		StagingDirectory::create_file(&directory, component(PART), component(TARGET), binding),
		Err(StageError::AlreadyExists)
	));
	assert_eq!(snapshot(&part_path), part_before);

	let reader = StageWriter::close_writes(writer).unwrap();
	assert_eq!(StageReader::identity(&reader), identity);
	assert_eq!(StageReader::length(&reader), extent);
	let mut readback = [0; PAYLOAD.len()];
	StageReader::read_exact_at(&reader, 0, &mut readback).unwrap();
	assert_eq!(readback, PAYLOAD);
	assert!(matches!(
		StageReader::read_exact_at(&reader, extent, &mut [0]),
		Err(IoError::InvalidRange { offset, length: 1 }) if offset == extent
	));

	let reader = StageReader::apply_metadata_with_access_time(reader, metadata, accessed).unwrap();
	StageReader::sync_stage_directory(&reader).unwrap();
	assert!(matches!(
		reader.inspect_selected_stream_location(),
		Err(StageError::MetadataMismatch)
	));
	let applied = fs::metadata(&part_path).unwrap();
	assert_eq!(applied.mode() & 0o777, SOURCE_MODE);
	assert_eq!(applied.atime(), accessed.seconds());
	assert_eq!(applied.atime_nsec(), i64::from(accessed.nanoseconds()));
	assert_eq!(
		(applied.dev(), applied.ino()),
		(identity.device(), identity.inode())
	);
	assert_eq!(fs::read(part_path).unwrap(), PAYLOAD);
	assert_eq!(snapshot(&source_path), source_before);
	assert_eq!(snapshot(&target_path), incumbent_before);
}

fn snapshot(path: &Path) -> (u64, u64, u32, Vec<u8>) {
	let metadata = fs::metadata(path).unwrap();
	(
		metadata.dev(),
		metadata.ino(),
		metadata.mode(),
		fs::read(path).unwrap(),
	)
}

fn component(value: &str) -> UnixComponent<'_> {
	UnixComponent::new(value.as_bytes()).unwrap()
}
