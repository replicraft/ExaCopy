use std::fs;
use std::os::unix::fs::MetadataExt as _;

use super::{FRESH, Fixture, INCUMBENT, NEW, OLD, ORIGINAL, StageError, TARGET, binding};

#[test]
fn fresh_preparation_rejects_busy_lease_then_stale_target_absence() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let previous = fixture.inventory(&lease, OLD);
	let vacant = fixture.inventory(&lease, FRESH);
	{
		let _directory = lease.reopen_stage_directory(&previous).unwrap();
		assert!(matches!(
			lease.prepare_fresh_stage(&vacant, fixture.directory),
			Err(StageError::JobBusy)
		));
	}
	let target = fixture.scratch.path(TARGET);
	fs::write(&target, INCUMBENT).unwrap();
	assert!(matches!(
		lease.prepare_fresh_stage(&vacant, fixture.directory),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(fs::read(target).unwrap(), INCUMBENT);
	assert_eq!(fs::read(fixture.stage(OLD)).unwrap(), ORIGINAL);
	assert!(!fixture.stage(FRESH).exists());
}

#[test]
fn fresh_writer_handoff_rejects_content_in_the_new_inode() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let vacant = fixture.inventory(&lease, FRESH);
	let mut prepared = lease
		.prepare_fresh_stage(&vacant, fixture.directory)
		.unwrap();
	let path = fixture.stage(FRESH);
	let mut created_inode = None;
	let result = prepared.create_with(binding(2), |directory| {
		let created = fs::metadata(&path).unwrap();
		assert_eq!(created.len(), 0);
		created_inode = Some(created.ino());
		fs::write(&path, NEW).unwrap();
		directory.sync_directory()
	});
	assert!(matches!(result, Err(StageError::IdentityChanged)));
	assert_eq!(Some(fs::metadata(&path).unwrap().ino()), created_inode);
	assert_eq!(fs::read(path).unwrap(), NEW);
	assert_eq!(fs::read(fixture.stage(OLD)).unwrap(), ORIGINAL);
	assert!(!fixture.scratch.path(TARGET).exists());
}
