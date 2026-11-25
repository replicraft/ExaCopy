use std::error::Error as _;
use std::fs::{self, DirBuilder, File};
use std::os::fd::AsFd as _;
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::process::Command;

use crate::macos::managed::acl;

use super::{
	DATA, Fixture, JobArtifact, RecoveryError, RecoveryName, STAGE, STAGE_BYTES, TARGET,
	TARGET_BYTES, job_name, job_path, name, open_staging,
};

#[test]
fn a_new_stage_directory_invalidates_observed_absence_and_preserves_the_incumbent() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	container.create_job_directory(job_name()).unwrap();
	let target = fixture.path(TARGET);
	fs::write(&target, TARGET_BYTES).expect("create an independent destination incumbent");
	let job = container.open_recovery_job(job_name()).unwrap();
	let staged_name = name(DATA.as_bytes());
	let target_name = name(TARGET.as_bytes());
	let before = job.inventory(staged_name, target_name).unwrap();
	assert_eq!(before.stage_directory_identity(), None);
	assert!(before.target().is_some());

	// Simulate an external change between two read-only observations.
	let stage = job_path(&fixture).join(STAGE);
	DirBuilder::new()
		.mode(0o700)
		.create(&stage)
		.expect("install a synthetic stage directory");
	let descriptor = File::open(&stage).expect("open the synthetic stage directory");
	acl::set_fixture_empty_acl(descriptor.as_fd()).expect("establish explicit empty stage ACL");
	let error = before
		.revalidate()
		.expect_err("a captured absence cannot remain valid after insertion");
	assert!(matches!(
		error,
		RecoveryError::InvalidObject(JobArtifact::Stage)
	));
	assert!(error.to_string().contains("Stage identity or metadata"));
	assert!(error.source().is_none());
	assert!(stage.is_dir());
	assert_eq!(fs::read(&target).unwrap(), TARGET_BYTES);

	let current = job.inventory(staged_name, target_name).unwrap();
	assert!(current.stage_directory_identity().is_some());
	assert_eq!(current.stage(), None);
	assert_eq!(current.target(), before.target());
	current.revalidate().unwrap();
}

#[test]
fn private_stage_refuses_widened_mode_and_acl_without_restricting_target_inventory() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	{
		let job = container.create_job_directory(job_name()).unwrap();
		job.create_stage_directory().unwrap();
	}
	let stage = job_path(&fixture).join(STAGE).join(DATA);
	let target = fixture.path(TARGET);
	fs::write(&stage, STAGE_BYTES).expect("create synthetic stage payload");
	fs::write(&target, TARGET_BYTES).expect("create synthetic incumbent");
	for path in [&stage, &target] {
		fs::set_permissions(path, fs::Permissions::from_mode(0o640))
			.expect("widen synthetic entry mode");
	}
	let job = container.open_recovery_job(job_name()).unwrap();
	let staged_name = name(DATA.as_bytes());
	let target_name = name(TARGET.as_bytes());
	let error = job
		.inventory(staged_name, target_name)
		.expect_err("a private stage cannot expose group rights");
	assert!(matches!(
		error,
		RecoveryError::InvalidEntry(RecoveryName::Stage)
	));
	assert!(error.to_string().contains("Stage identity or metadata"));

	fs::set_permissions(&stage, fs::Permissions::from_mode(0o600))
		.expect("restore owner-private mode");
	{
		let clean = job.inventory(staged_name, target_name).unwrap();
		assert_eq!(clean.stage().unwrap().length(), STAGE_BYTES.len() as u64);
		assert_eq!(clean.target().unwrap().length(), TARGET_BYTES.len() as u64);
	}
	assert!(
		Command::new("/bin/chmod")
			.args(["+a", "everyone allow read"])
			.arg(&stage)
			.status()
			.expect("grant synthetic stage ACL")
			.success()
	);
	assert!(matches!(
		job.inventory(staged_name, target_name),
		Err(RecoveryError::InvalidEntry(RecoveryName::Stage))
	));
	assert_eq!(fs::read(&stage).unwrap(), STAGE_BYTES);
	assert_eq!(fs::read(&target).unwrap(), TARGET_BYTES);
}

#[test]
fn same_length_target_replacement_invalidates_inventory_and_retains_both_inodes() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	container.create_job_directory(job_name()).unwrap();
	let path = fixture.path(TARGET);
	fs::write(&path, TARGET_BYTES).expect("create synthetic target");
	let job = container.open_recovery_job(job_name()).unwrap();
	let staged_name = name(DATA.as_bytes());
	let target_name = name(TARGET.as_bytes());
	let before = job.inventory(staged_name, target_name).unwrap();
	let retained = fixture.path("original-target");
	fs::rename(&path, &retained).expect("retain original synthetic inode");
	let replacement = vec![b'x'; TARGET_BYTES.len()];
	fs::write(&path, &replacement).expect("install independent inode with the same extent");

	let error = before
		.revalidate()
		.expect_err("equal extents do not establish namespace identity");
	assert!(matches!(
		error,
		RecoveryError::InvalidEntry(RecoveryName::Target)
	));
	assert!(error.to_string().contains("Target identity or metadata"));
	let current = job.inventory(staged_name, target_name).unwrap();
	let old_entry = before.target().unwrap();
	let new_entry = current.target().unwrap();
	assert_eq!(old_entry.length(), new_entry.length());
	assert_ne!(old_entry.identity(), new_entry.identity());
	assert_eq!(fs::read(retained).unwrap(), TARGET_BYTES);
	assert_eq!(fs::read(path).unwrap(), replacement);
}
