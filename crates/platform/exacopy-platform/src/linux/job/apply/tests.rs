use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_apply::{
	ApplyJobRecord, ApplyRole, ApplyStep, GuardedCopyJob, GuardedJobRoot, HeldJobRecord,
};

use super::{DestinationRoot, JobDirectoryCreationError, StageError};
use crate::linux::guarded_staging::tests::FixtureAdmission;
use crate::scratch::Scratch;

#[test]
fn private_job_and_record_refusal_preserve_the_preceding_native_boundary() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let gate = FixtureAdmission::default();
	let job_scope = UnixComponent::new(b"job").unwrap();
	let job_path = scratch.path("job");
	gate.refuse.set(Some(ApplyStep::Create(ApplyRole::Job)));
	assert!(matches!(
		root.create_job_admitted(job_scope, &gate),
		Err(JobDirectoryCreationError::NotCreated(
			StageError::Admission(_)
		))
	));
	assert!(!job_path.exists());
	gate.refuse.set(Some(ApplyStep::Create(ApplyRole::Owner)));
	let job = root.create_job_admitted(job_scope, &gate).unwrap();
	assert!(matches!(
		job.seal_job_record(ApplyJobRecord::Owner, b"owner", &gate),
		Err(StageError::Admission(_))
	));
	assert!(!job_path.join("owner.cbor").exists());
	gate.refuse
		.set(Some(ApplyStep::Write(ApplyRole::PrivatePlan, 0, 4)));
	assert!(matches!(
		job.seal_job_record(ApplyJobRecord::PrivatePlan, b"plan", &gate),
		Err(StageError::Admission(_))
	));
	assert_eq!(fs::read(job_path.join("plan.cbor")).unwrap(), b"");
	assert!(!job_path.join("journal").exists());
	assert_eq!(
		gate.steps.into_inner(),
		[
			ApplyStep::Create(ApplyRole::Job),
			ApplyStep::Create(ApplyRole::Job),
			ApplyStep::Create(ApplyRole::Owner),
			ApplyStep::Create(ApplyRole::PrivatePlan),
			ApplyStep::Write(ApplyRole::PrivatePlan, 0, 4),
		]
	);
}

#[test]
fn held_owner_and_plan_reject_same_byte_name_rebinding_and_preserve_both_inodes() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let gate = FixtureAdmission::default();
	let job = root
		.create_job_admitted(UnixComponent::new(b"job").unwrap(), &gate)
		.unwrap();
	for (role, filename) in [
		(ApplyJobRecord::Owner, "owner.cbor"),
		(ApplyJobRecord::PrivatePlan, "plan.cbor"),
	] {
		let path = scratch.path("job").join(filename);
		let saved = scratch.path("job").join(format!("saved-{filename}"));
		let pin = job.seal_job_record(role, b"exact input", &gate).unwrap();
		let original = fs::symlink_metadata(&path).unwrap();
		let mut bytes = [0; 11];
		pin.read_exact_job_record(&job, &mut bytes).unwrap();
		assert_eq!(&bytes, b"exact input");
		assert_eq!(pin.file.metadata().unwrap().ino(), original.ino());

		// The test owns both entries and deliberately violates the cooperative lease.
		fs::rename(&path, &saved).unwrap();
		fs::write(&path, b"exact input").unwrap();
		fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
		let replacement = fs::symlink_metadata(&path).unwrap();
		assert_ne!(
			(replacement.dev(), replacement.ino()),
			(original.dev(), original.ino())
		);
		bytes.fill(0x35);
		assert!(matches!(
			pin.read_exact_job_record(&job, &mut bytes),
			Err(StageError::IdentityChanged)
		));
		assert_eq!(bytes, [0x35; 11]);
		assert_eq!(fs::symlink_metadata(&saved).unwrap().ino(), original.ino());
		assert_eq!(
			fs::symlink_metadata(&path).unwrap().ino(),
			replacement.ino()
		);
		assert_eq!(fs::read(&saved).unwrap(), b"exact input");
		assert_eq!(fs::read(&path).unwrap(), b"exact input");
	}
}
