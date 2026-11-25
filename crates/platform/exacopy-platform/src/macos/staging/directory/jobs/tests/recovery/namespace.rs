use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, symlink};

use super::super::{DATA, RECEIPT, RECEIPTS, STAGE, job_context, name};
use super::{Fixture, RecoveryError, TARGET, job_name, job_path, open_staging};
use crate::macos::staging::jobs::{JobArtifact, RecoveryName};

mod revalidation;

const RECEIPT_BYTES: &[u8] = b"opaque immutable receipt fixture";
const STAGE_BYTES: &[u8] = b"private observed extent";
const TARGET_BYTES: &[u8] = b"unrelated target extent";

#[test]
fn observes_missing_receipt_and_reads_the_fixed_receipt_under_lease() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	{
		container.create_job_directory(job_name()).unwrap();
		assert!(
			container
				.open_recovery_job(job_name())
				.unwrap()
				.open_receipt()
				.unwrap()
				.is_none()
		);
	}
	let other_fixture = Fixture::new();
	let other_root = other_fixture.bind();
	let other_container = open_staging(&other_root);
	let identity = {
		let job = other_container.create_job_directory(job_name()).unwrap();
		let receipts = job.create_receipt_directory().unwrap();
		receipts.write_receipt(RECEIPT_BYTES).unwrap()
	};
	let job = other_container.open_recovery_job(job_name()).unwrap();
	let mut receipt = job.open_receipt().unwrap().unwrap();
	assert_eq!(receipt.identity(), identity);
	assert!(matches!(
		job.open_receipt(),
		Err(RecoveryError::DirectoryBusy(JobArtifact::Receipts))
	));
	let mut bytes = Vec::new();
	receipt.read_to_end(&mut bytes).unwrap();
	receipt.revalidate().unwrap();
	assert_eq!(bytes, RECEIPT_BYTES);
	assert_eq!(
		fs::read(job_path(&other_fixture).join(RECEIPTS).join(RECEIPT)).unwrap(),
		RECEIPT_BYTES
	);
}

#[test]
fn an_empty_receipt_directory_observes_absence_but_a_symlink_refuses() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	{
		let job = container.create_job_directory(job_name()).unwrap();
		job.create_receipt_directory().unwrap();
	}
	let job = container.open_recovery_job(job_name()).unwrap();
	assert!(job.open_receipt().unwrap().is_none());

	let external = fixture.path(TARGET);
	fs::write(&external, TARGET_BYTES).unwrap();
	let receipt = job_path(&fixture).join(RECEIPTS).join(RECEIPT);
	symlink(&external, &receipt).unwrap();
	assert!(matches!(
		job.open_receipt(),
		Err(RecoveryError::InvalidObject(JobArtifact::Receipt))
	));
	assert_eq!(fs::read_link(&receipt).unwrap(), external);
	assert_eq!(fs::read(&external).unwrap(), TARGET_BYTES);
}

#[test]
fn stage_and_target_distinguish_held_regular_inodes_with_separate_identities() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	let staged_name = name(DATA.as_bytes());
	let target_name = name(TARGET.as_bytes());
	let (directory_identity, staged_identity) = {
		let job = container.create_job_directory(job_name()).unwrap();
		let stage = job.create_stage_directory().unwrap();
		let mut writer = stage
			.create_file(
				staged_name,
				target_name,
				job_context(),
				STAGE_BYTES.len() as u64,
			)
			.unwrap();
		writer.write_next(STAGE_BYTES).unwrap();
		let closed = writer.flush_and_close().unwrap();
		(
			stage.observe_identity().unwrap(),
			closed.observe_identity().unwrap(),
		)
	};
	let target = fixture.path(TARGET);
	fs::write(&target, TARGET_BYTES).unwrap();

	let job = container.open_recovery_job(job_name()).unwrap();
	let inventory = job.inventory(staged_name, target_name).unwrap();
	assert_eq!(
		inventory.stage_directory_identity(),
		Some(directory_identity)
	);
	let stage = inventory.stage().unwrap();
	assert_eq!(stage.identity(), staged_identity);
	assert_eq!(stage.length(), STAGE_BYTES.len() as u64);
	let observed_target = inventory.target().unwrap();
	assert_eq!(
		observed_target.identity().inode().get(),
		fs::metadata(&target).unwrap().ino()
	);
	assert_eq!(
		observed_target.identity().physical_fsid(),
		staged_identity.physical_fsid()
	);
	assert_ne!(observed_target.identity(), staged_identity);
	assert_eq!(observed_target.length(), TARGET_BYTES.len() as u64);
	assert!(matches!(
		job.inventory(staged_name, target_name),
		Err(RecoveryError::DirectoryBusy(JobArtifact::Stage))
	));
	inventory.revalidate().unwrap();
	assert_eq!(
		fs::read(job_path(&fixture).join(STAGE).join(DATA)).unwrap(),
		STAGE_BYTES
	);
	assert_eq!(fs::read(&target).unwrap(), TARGET_BYTES);
}

#[test]
fn missing_names_are_revalidated_and_unsafe_occupants_never_become_absence() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	{
		container.create_job_directory(job_name()).unwrap();
	}
	let job = container.open_recovery_job(job_name()).unwrap();
	let stage_name = name(DATA.as_bytes());
	let target_name = name(TARGET.as_bytes());
	let empty = job.inventory(stage_name, target_name).unwrap();
	assert_eq!(empty.stage_directory_identity(), None);
	assert_eq!(empty.stage(), None);
	assert_eq!(empty.target(), None);
	empty.revalidate().unwrap();

	// Synthetic namespace change between observations.
	let path = fixture.path(TARGET);
	let unrelated = fixture.path("outside-recovery");
	File::options()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&unrelated)
		.unwrap()
		.write_all(TARGET_BYTES)
		.unwrap();
	symlink(&unrelated, &path).unwrap();
	assert!(matches!(
		empty.revalidate(),
		Err(RecoveryError::InvalidEntry(RecoveryName::Target))
	));
	assert!(matches!(
		job.inventory(stage_name, target_name),
		Err(RecoveryError::InvalidEntry(RecoveryName::Target))
	));
	assert_eq!(fs::read_link(&path).unwrap(), unrelated);

	let alias = fixture.path("hard-linked-target");
	fs::hard_link(&unrelated, alias).unwrap();
	assert!(matches!(
		job.inventory(stage_name, name(b"hard-linked-target")),
		Err(RecoveryError::InvalidEntry(RecoveryName::Target))
	));
	assert_eq!(fs::read(&unrelated).unwrap(), TARGET_BYTES);
}

#[test]
fn held_stage_directory_and_absent_payload_are_independent_observations() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	{
		let job = container.create_job_directory(job_name()).unwrap();
		job.create_stage_directory().unwrap();
	}
	let job = container.open_recovery_job(job_name()).unwrap();
	let stage_name = name(DATA.as_bytes());
	let target_name = name(TARGET.as_bytes());
	let before = job.inventory(stage_name, target_name).unwrap();
	assert!(before.stage_directory_identity().is_some());
	assert_eq!(before.stage(), None);
	assert_eq!(before.target(), None);

	let path = job_path(&fixture).join(STAGE).join(DATA);
	symlink(fixture.path(TARGET), &path).unwrap();
	assert!(matches!(
		before.revalidate(),
		Err(RecoveryError::InvalidEntry(RecoveryName::Stage))
	));
	drop(before);
	assert!(matches!(
		job.inventory(stage_name, target_name),
		Err(RecoveryError::InvalidEntry(RecoveryName::Stage))
	));
}
