use std::fs;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::MetadataExt as _;

use exacopy_endpoint::UnixComponent;

use super::{DestinationRoot, StageError};
use crate::scratch::Scratch;

const PRIVATE_DIR: &str = "transaction-stage";
const RECORD: &str = "transaction-record";

#[test]
fn record_creation_is_private_exclusive_and_bound_to_held_directories() {
	let fixture = Scratch::new();
	let destination = DestinationRoot::from_directory(fixture.open()).expect("destination root");
	let stage = destination
		.create_stage_directory(component(PRIVATE_DIR))
		.expect("create private stage directory");
	const PAYLOAD: &[u8] = b"bounded transaction record";
	let mut record = stage
		.create_record(component(RECORD))
		.expect("create private record");
	record.write_all(PAYLOAD).expect("complete write");
	record.sync_all().expect("record data barrier");
	stage.sync_directory().expect("stage name barrier");
	destination
		.sync_directory()
		.expect("destination name barrier");
	assert_ne!(stage.identity(), destination.identity());

	record.seek(SeekFrom::Start(0)).expect("rewind held record");
	let mut read_back = [0; PAYLOAD.len()];
	record
		.read_exact(&mut read_back)
		.expect("read through the held private descriptor");
	assert_eq!(&read_back, PAYLOAD);
	let stat = record.metadata().expect("record metadata");
	assert_eq!(stat.mode() & 0o7777, 0o600);
	assert_eq!(stat.nlink(), 1);
	assert!(matches!(
		stage.create_record(component(RECORD)),
		Err(StageError::AlreadyExists)
	));
	assert_eq!(
		fs::read(fixture.path(PRIVATE_DIR).join(RECORD)).expect("retain private record"),
		PAYLOAD
	);
	assert!(!fixture.path(RECORD).exists());
}

#[test]
fn stage_directory_barriers_and_record_creation_refuse_rebinding() {
	let fixture = Scratch::new();
	let destination = DestinationRoot::from_directory(fixture.open()).expect("destination root");
	let stage = destination
		.create_stage_directory(component(PRIVATE_DIR))
		.expect("create private stage directory");
	let original = fixture.path(PRIVATE_DIR);
	let displaced = fixture.path("displaced-stage");
	fs::rename(&original, &displaced).expect("move the private fixture directory");
	let _ = destination
		.create_stage_directory(component(PRIVATE_DIR))
		.expect("rebind the same name to a different owned directory");

	assert!(matches!(
		stage.sync_directory(),
		Err(StageError::IdentityChanged)
	));
	assert!(matches!(
		stage.create_record(component(RECORD)),
		Err(StageError::IdentityChanged)
	));
	assert!(!original.join(RECORD).exists());
	assert!(!displaced.join(RECORD).exists());
}

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).expect("valid fixture component")
}
