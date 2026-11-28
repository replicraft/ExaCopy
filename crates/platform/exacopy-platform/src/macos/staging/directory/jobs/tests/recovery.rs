use std::fs::{self, File};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, symlink};
use std::path::Path;

use crate::macos::ManagedReadError;
use crate::macos::staging::jobs::with_provisioned_recovery_job;
use crate::macos::staging::{ManagedStageGrant, StageError};

use super::super::RecoveryError;
use super::{
	FIRST_SEGMENT, Fixture, JOB_NAME, JOURNAL, JobArtifact, JobName, OWNER, PLAN, PRIVATE, TARGET,
	UUID, job_name, job_path, name, open_staging,
};

mod namespace;
mod readback;
const OWNER_BYTES: &[u8] = b"opaque owner fixture";
const PLAN_BYTES: &[u8] = b"opaque canonical plan fixture";
const JOURNAL_BYTES: &[u8] = b"opaque journal prefix";

#[test]
fn provisioned_path_inspection_holds_the_existing_job_and_destination_lease() {
	let fixture = Fixture::new();
	let destination = fixture.path(PRIVATE).parent().unwrap().to_path_buf();
	let grant = ManagedStageGrant::trusted_owner_authorizes_provisioned_root;
	let (root_identity, job_identity, owner_identity) = {
		let root = fixture.bind();
		let container = open_staging(&root);
		let job = container.create_job_directory(job_name()).unwrap();
		let owner = job.write_owner_record(OWNER_BYTES).unwrap();
		(root.observe_identity().unwrap(), job.identity(), owner)
	};
	fs::write(fixture.path(TARGET), PLAN_BYTES).unwrap();
	let observed = with_provisioned_recovery_job(
		&destination,
		name(PRIVATE.as_bytes()),
		job_name(),
		grant(),
		|job| {
			assert_eq!(job.identity(), job_identity);
			assert_eq!(job.observe_destination().unwrap(), root_identity);
			let nested = with_provisioned_recovery_job(
				&destination,
				name(PRIVATE.as_bytes()),
				job_name(),
				grant(),
				|_| (),
			);
			assert!(matches!(
				nested,
				Err(RecoveryError::Managed(StageError::DirectoryBusy))
			));
			let mut owner = job.open_owner().unwrap();
			assert_eq!(owner.identity(), owner_identity);
			let mut bytes = Vec::new();
			owner.read_to_end(&mut bytes).unwrap();
			owner.revalidate().unwrap();
			bytes
		},
	)
	.unwrap();
	assert_eq!(observed, OWNER_BYTES);
	assert_eq!(
		fs::read(job_path(&fixture).join(OWNER)).unwrap(),
		OWNER_BYTES
	);
	assert_eq!(fs::read(fixture.path(TARGET)).unwrap(), PLAN_BYTES);
	assert_eq!(fixture.bind().observe_identity().unwrap(), root_identity);
}

#[test]
fn provisioned_path_inspection_refuses_untrusted_lookup_without_creating_entries() {
	let fixture = Fixture::new();
	let destination = fixture.path(PRIVATE).parent().unwrap().to_path_buf();
	let path_link = fixture.path("root-link");
	symlink(&destination, &path_link).unwrap();
	let container_link = fixture.path("container-link");
	symlink(fixture.path(PRIVATE), &container_link).unwrap();

	let inspect = |destination: &Path, container: &[u8]| {
		with_provisioned_recovery_job(
			destination,
			name(container),
			job_name(),
			ManagedStageGrant::trusted_owner_authorizes_provisioned_root(),
			|_| (),
		)
	};
	assert!(inspect(&destination, b"missing-container").is_err());
	assert!(matches!(
		inspect(&destination, PRIVATE.as_bytes()),
		Err(RecoveryError::Missing(JobArtifact::Directory))
	));
	assert!(!fixture.path("missing-container").exists());
	assert!(!job_path(&fixture).exists());

	// Seed an admissible job so following either symlink would reach the callback.
	{
		let root = fixture.bind();
		let container = open_staging(&root);
		let job = container.create_job_directory(job_name()).unwrap();
		job.write_owner_record(OWNER_BYTES).unwrap();
	}
	assert!(inspect(&destination, PRIVATE.as_bytes()).is_ok());
	for path in [Path::new("relative"), &fixture.path("private-stage/..")] {
		assert!(matches!(
			inspect(path, PRIVATE.as_bytes()),
			Err(RecoveryError::Managed(StageError::Managed(
				ManagedReadError::UnsupportedNamespace,
			)))
		));
	}
	assert!(inspect(&path_link, PRIVATE.as_bytes()).is_err());
	assert!(inspect(&destination, b"container-link").is_err());
	assert!(inspect(&destination, PRIVATE.as_bytes()).is_ok());
	assert_eq!(fs::read_link(&path_link).unwrap(), destination);
	assert_eq!(
		fs::read_link(&container_link).unwrap(),
		fixture.path(PRIVATE)
	);
	assert_eq!(
		fs::read(job_path(&fixture).join(OWNER)).unwrap(),
		OWNER_BYTES
	);
}

#[test]
fn reopens_only_fixed_artifacts_with_matching_observed_identities() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	let (job_identity, owner_uid, owner_identity, plan_identity) = {
		let job = container.create_job_directory(job_name()).unwrap();
		let owner = job.write_owner_record(OWNER_BYTES).unwrap();
		let plan = job.write_plan_record(PLAN_BYTES).unwrap();
		let journal = job.create_journal_directory().unwrap();
		let mut segment = journal.create_first_segment().unwrap();
		segment.write_all(JOURNAL_BYTES).unwrap();
		(job.identity(), job.owner_uid(), owner, plan)
	};

	let job = container.open_recovery_job(job_name()).unwrap();
	assert_eq!(job.name(), job_name());
	assert_eq!(job.identity(), job_identity);
	assert_eq!(job.owner_uid(), owner_uid);
	assert_eq!(
		job.observe_destination().unwrap(),
		root.observe_identity().unwrap()
	);
	let owner = job.open_owner().unwrap();
	assert_eq!(owner.identity(), owner_identity);
	let plan = job.open_plan().unwrap();
	assert_eq!(plan.identity(), plan_identity);
	let segment = job.open_first_segment().unwrap();
	for (mut record, expected) in [
		(owner, OWNER_BYTES),
		(plan, PLAN_BYTES),
		(segment, JOURNAL_BYTES),
	] {
		let mut bytes = Vec::new();
		assert_eq!(record.len(), expected.len() as u64);
		record.read_to_end(&mut bytes).unwrap();
		record.revalidate().unwrap();
		assert_eq!(bytes, expected);
	}
	assert!(!fixture.path(TARGET).exists());
	assert_eq!(
		fs::read(job_path(&fixture).join(OWNER)).unwrap(),
		OWNER_BYTES
	);
	assert_eq!(fs::read(job_path(&fixture).join(PLAN)).unwrap(), PLAN_BYTES);
	assert_eq!(
		fs::read(job_path(&fixture).join(JOURNAL).join(FIRST_SEGMENT)).unwrap(),
		JOURNAL_BYTES
	);
}

#[test]
fn refuses_conflicting_job_and_journal_leases_and_nested_stage_directories() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	{
		let job = container.create_job_directory(job_name()).unwrap();
		assert!(matches!(
			container.open_recovery_job(job_name()),
			Err(RecoveryError::DirectoryBusy(JobArtifact::Directory))
		));
		let stage = job.create_stage_directory().unwrap();
		assert!(matches!(
			stage.open_recovery_job(job_name()),
			Err(RecoveryError::NestedJob)
		));
		job.create_journal_directory()
			.unwrap()
			.create_first_segment()
			.unwrap();
	}
	let job = container.open_recovery_job(job_name()).unwrap();
	let mut first = job.open_first_segment().unwrap();
	assert!(first.is_empty());
	assert_eq!(first.read(&mut [0]).unwrap(), 0);
	assert!(matches!(
		job.open_first_segment(),
		Err(RecoveryError::DirectoryBusy(JobArtifact::Journal))
	));
	drop(first);
	assert!(job.open_first_segment().unwrap().is_empty());
}

#[test]
fn rejects_wrong_names_symlinks_aliases_and_hard_links() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	let mut wrong = UUID;
	wrong[0] ^= 1;
	let wrong = JobName::from_uuid_bytes(wrong).unwrap();
	let path = job_path(&fixture);
	{
		let job = container.create_job_directory(job_name()).unwrap();
		job.write_owner_record(OWNER_BYTES).unwrap();
	}
	assert!(matches!(
		container.open_recovery_job(wrong),
		Err(RecoveryError::Missing(JobArtifact::Directory))
	));
	let alias = fixture.path(PRIVATE).join(JOB_NAME.to_uppercase());
	let displaced = fixture.path(PRIVATE).join("displaced-job");
	fs::rename(&path, &displaced).unwrap();
	symlink(&displaced, &path).unwrap();
	assert!(matches!(
		container.open_recovery_job(job_name()),
		Err(RecoveryError::InvalidObject(JobArtifact::Directory))
	));
	fs::remove_file(&path).unwrap();
	fs::rename(&displaced, &alias).unwrap();
	match container.open_recovery_job(job_name()) {
		Err(RecoveryError::InvalidObject(JobArtifact::Directory)) if path.exists() => {}
		Err(RecoveryError::Missing(JobArtifact::Directory)) if !path.exists() => {}
		result => panic!("case alias unexpectedly admitted: {result:?}"),
	}
	fs::rename(&alias, &displaced).unwrap();
	fs::rename(&displaced, &path).unwrap();

	let outside = fixture.path(TARGET);
	fs::write(&outside, PLAN_BYTES).unwrap();
	let private = path.join(PLAN);
	symlink(&outside, &private).unwrap();
	let job = container.open_recovery_job(job_name()).unwrap();
	assert!(matches!(
		job.open_plan(),
		Err(RecoveryError::InvalidObject(JobArtifact::Plan))
	));
	assert_eq!(fs::read_link(&private).unwrap(), outside);
	fs::remove_file(&private).unwrap();
	fs::hard_link(path.join(OWNER), &private).unwrap();
	assert!(matches!(
		job.open_plan(),
		Err(RecoveryError::InvalidObject(JobArtifact::Plan))
	));
	assert_eq!(fs::read(&outside).unwrap(), PLAN_BYTES);
	assert_eq!(fs::read(&private).unwrap(), OWNER_BYTES);
}

#[test]
fn rejects_record_bounds_before_reading() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	let journal_path = job_path(&fixture).join(JOURNAL).join(FIRST_SEGMENT);
	{
		let job = container.create_job_directory(job_name()).unwrap();
		let mut oversized = job
			.create_journal_directory()
			.unwrap()
			.create_first_segment()
			.unwrap();
		oversized.seek(SeekFrom::Start(64 * 1024 * 1024)).unwrap();
		oversized.write_all(&[0]).unwrap();
	}
	let empty = job_path(&fixture).join(OWNER);
	File::options()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&empty)
		.unwrap();
	let job = container.open_recovery_job(job_name()).unwrap();
	assert!(matches!(
		job.open_owner(),
		Err(RecoveryError::InvalidLength {
			artifact: JobArtifact::Owner,
			length: 0,
			..
		})
	));
	assert!(matches!(
		job.open_first_segment(),
		Err(RecoveryError::InvalidLength {
			artifact: JobArtifact::FirstSegment,
			length,
			limit
		}) if length == limit + 1
	));
	assert_eq!(fs::metadata(&empty).unwrap().len(), 0);
	assert_eq!(
		fs::metadata(&journal_path).unwrap().len(),
		64 * 1024 * 1024 + 1
	);
}

#[test]
fn revalidation_detects_replaced_record_and_keeps_both_objects() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let container = open_staging(&root);
	{
		let job = container.create_job_directory(job_name()).unwrap();
		job.write_owner_record(OWNER_BYTES).unwrap();
	}
	let job = container.open_recovery_job(job_name()).unwrap();
	let mut owner = job.open_owner().unwrap();
	let path = job_path(&fixture).join(OWNER);
	let retained = path.with_extension("original");
	// Deliberately break the cooperative namespace contract in this synthetic fixture.
	fs::rename(&path, &retained).unwrap();
	File::options()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&path)
		.unwrap()
		.write_all(PLAN_BYTES)
		.unwrap();
	assert!(matches!(
		owner.revalidate(),
		Err(RecoveryError::InvalidObject(JobArtifact::Owner))
	));
	let mut bytes = [0; 8];
	assert!(owner.read(&mut bytes).is_err());
	assert_eq!(bytes, [0; 8]);
	assert_eq!(fs::read(&retained).unwrap(), OWNER_BYTES);
	assert_eq!(fs::read(&path).unwrap(), PLAN_BYTES);
}
