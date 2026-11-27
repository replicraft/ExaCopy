use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt as _;

use exacopy_endpoint::UnixComponent;

use super::{CHECKPOINTS, DATA, FIRST_PAGE, JOB, job_name};
use crate::linux::{DestinationRoot, StageError, TargetStatus};
use crate::scratch::Scratch;

#[test]
fn weakened_destination_refuses_target_observation_and_checkpoint_write() {
	let fixture = Scratch::new();
	let destination = fixture.path("destination");
	fs::create_dir(&destination).expect("create managed destination");
	fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))
		.expect("set owner-private destination mode");
	let root = DestinationRoot::from_directory(fs::File::open(&destination).expect("open root"))
		.expect("hold managed destination");
	let job = root.create_job_directory(job_name()).expect("private job");
	let checkpoints = job
		.create_checkpoint_directory()
		.expect("private checkpoints");
	checkpoints
		.write_page(1, &DATA)
		.expect("persist first page");
	let incumbent = destination.join("incumbent");
	let target = UnixComponent::new(b"incumbent").expect("target component");
	fs::write(&incumbent, b"keep incumbent").expect("seed incumbent");
	assert_eq!(
		root.target_status(target).expect("observe occupied target"),
		TargetStatus::Occupied
	);

	fs::set_permissions(&destination, fs::Permissions::from_mode(0o770))
		.expect("grant group write without the sticky bit");
	assert!(matches!(
		root.target_status(target),
		Err(StageError::UnsafeDirectory)
	));
	assert!(matches!(
		checkpoints.write_page(2, &[0x55]),
		Err(StageError::UnsafeDirectory)
	));

	let pages = destination.join(JOB).join(CHECKPOINTS);
	assert_eq!(
		fs::read(pages.join(FIRST_PAGE)).expect("read retained first page"),
		DATA
	);
	assert_eq!(
		fs::symlink_metadata(pages.join("range-0000000002.cbor"))
			.expect_err("unsafe root cannot acquire a second checkpoint page")
			.kind(),
		ErrorKind::NotFound
	);
	assert_eq!(
		fs::read(incumbent).expect("read retained incumbent"),
		b"keep incumbent"
	);
}
