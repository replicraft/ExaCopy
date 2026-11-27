use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt as _;

use super::{Fixture, INCUMBENT, JOB, ORIGINAL, PART, SOURCE, STAGE, StageError, TARGET};
use super::{binding, component, inventory};

#[test]
fn directory_reopen_rejects_missing_stage_and_captured_or_late_incumbent() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let missing_name = "missing-stage";
	let missing = lease
		.job()
		.inventory(component(missing_name), component(TARGET))
		.unwrap();
	assert!(matches!(
		lease.reopen_stage_directory(&missing),
		Err(StageError::IdentityChanged)
	));
	let vacant = inventory(&lease);
	let target = fixture.target();
	fs::write(&target, INCUMBENT).unwrap();
	let occupied = inventory(&lease);
	assert!(matches!(
		lease.reopen_stage_directory(&occupied),
		Err(StageError::IdentityChanged)
	));
	assert!(matches!(
		lease.reopen_stage_directory(&vacant),
		Err(StageError::IdentityChanged)
	));
	occupied.recheck().unwrap();
	assert_eq!(fs::read(target).unwrap(), INCUMBENT);
	assert_eq!(fs::read(fixture.stage()).unwrap(), ORIGINAL);
	assert!(!fixture.stage().with_file_name(missing_name).exists());
}

#[test]
fn readback_reopen_rejects_target_appearing_after_directory_preflight() {
	let fixture = Fixture::new();
	let source = fixture.read_only_source();
	fs::set_permissions(fixture.stage(), Permissions::from_mode(0o444)).unwrap();
	let lease = fixture.lease();
	let captured = inventory(&lease);
	let mut directory = lease.reopen_stage_directory(&captured).unwrap();
	let target = fixture.target();
	fs::write(&target, INCUMBENT).unwrap();
	assert!(matches!(
		directory.open_flushed_readback(binding(), source),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(fs::read(target).unwrap(), INCUMBENT);
	assert_eq!(fs::read(fixture.stage()).unwrap(), ORIGINAL);
	assert_eq!(fs::read(fixture.scratch.path(SOURCE)).unwrap(), ORIGINAL);
}

#[test]
fn recovered_directory_barrier_rejects_a_rebound_private_directory() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let captured = inventory(&lease);
	let directory = lease.reopen_stage_directory(&captured).unwrap();
	directory.sync_directory().unwrap();

	let job = fixture.scratch.path(JOB);
	let current = job.join(STAGE);
	let retained = job.join("retained-private-directory");
	fs::rename(&current, &retained).unwrap();
	fs::create_dir(&current).unwrap();
	fs::set_permissions(&current, Permissions::from_mode(0o700)).unwrap();
	assert!(matches!(
		directory.sync_directory(),
		Err(StageError::IdentityChanged)
	));
	assert!(!fixture.stage().exists());
	assert_eq!(fs::read(retained.join(PART)).unwrap(), ORIGINAL);
	assert!(!fixture.target().exists());
}
