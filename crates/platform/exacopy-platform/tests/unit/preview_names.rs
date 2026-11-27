use std::fs::{self, File};
use std::os::unix::fs::MetadataExt as _;

use rustix::io::Errno;

use super::*;
use crate::scratch::Scratch;

#[test]
fn a_regular_file_cannot_supply_a_directory_observation() {
	let fixture = Scratch::new();
	let path = fixture.path("regular");
	let payload = b"owned regular-file bytes";
	fs::write(&path, payload).expect("create the owned non-directory control");
	let file = File::open(&path).expect("hold the regular file read-only");
	let name = UnixComponent::new(b"absent").expect("use a valid component");

	assert!(matches!(
		confirm(&file, name, None),
		Err(SyncPreviewError::System(error)) if Errno::from_io_error(&error) == Some(Errno::NOTDIR)
	));
	assert_eq!(
		fs::read(&path).expect("read the original contents"),
		payload
	);
}

#[test]
fn a_detached_directory_cannot_certify_absence() {
	let fixture = Scratch::new();
	let path = fixture.path("detachable");
	fs::create_dir(&path).expect("create an empty owned directory");
	let directory = File::open(&path).expect("hold the directory read-only");
	let name = UnixComponent::new(b"absent").expect("use a valid component");
	confirm(&directory, name, None).expect("confirm absence in an attached empty directory");

	fs::remove_dir(&path).expect("detach only the owned empty directory");
	assert_eq!(
		directory
			.metadata()
			.expect("inspect the held directory")
			.nlink(),
		0,
		"the held directory has no linked name"
	);
	assert!(matches!(
		confirm(&directory, name, None),
		Err(SyncPreviewError::System(error)) if Errno::from_io_error(&error) == Some(Errno::NOENT)
	));
}
