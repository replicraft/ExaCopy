use std::fs;
use std::os::unix::fs::MetadataExt as _;

use super::{DIRECTORY, PART, PAYLOAD, TARGET, component, stage};
use crate::linux::{DestinationRoot, StageError};
use crate::scratch::Scratch;

#[test]
fn refuses_admission_and_keeps_private_stage_and_incumbent() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let directory = root.create_stage_directory(component(DIRECTORY)).unwrap();
	let stage = stage(&directory, PAYLOAD);
	let part = scratch.path(DIRECTORY).join(PART);
	let target = scratch.path(TARGET);
	fs::write(&target, b"incumbent").unwrap();
	let stage_before = fs::metadata(&part).unwrap();
	let target_before = fs::metadata(&target).unwrap();
	let length = stage.length();

	let result = stage.prepare_selected_stream_metadata_admitted(length, || {
		Err::<(), _>(std::io::ErrorKind::PermissionDenied.into())
	});

	assert!(matches!(
		result,
		Err(StageError::Admission(error)) if error.kind() == std::io::ErrorKind::PermissionDenied
	));
	let stage_after = fs::metadata(&part).unwrap();
	let target_after = fs::metadata(&target).unwrap();
	assert_eq!(
		(stage_after.dev(), stage_after.ino()),
		(stage_before.dev(), stage_before.ino())
	);
	assert_eq!(
		(target_after.dev(), target_after.ino()),
		(target_before.dev(), target_before.ino())
	);
	assert_eq!(fs::read(part).unwrap(), PAYLOAD);
	assert_eq!(fs::read(target).unwrap(), b"incumbent");
}
