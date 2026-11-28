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

#[test]
fn private_record_bounds_refuse_before_effects_and_accept_the_full_native_ceiling() {
	for (record, name) in [
		(ApplyJobRecord::Owner, "owner.cbor"),
		(ApplyJobRecord::PrivatePlan, "plan.cbor"),
	] {
		let scratch = Scratch::new();
		let root = DestinationRoot::from_directory(scratch.open()).unwrap();
		let gate = FixtureAdmission::default();
		let job = root
			.create_job_admitted(UnixComponent::new(b"job").unwrap(), &gate)
			.unwrap();
		gate.steps.borrow_mut().clear();
		// These native apertures bound bytes, independently of either artifact codec.
		for bytes in [Vec::new(), vec![0x61; 65_537]] {
			assert!(matches!(
				job.seal_job_record(record, &bytes, &gate),
				Err(StageError::InvalidLength)
			));
			assert!(gate.steps.borrow().is_empty());
			assert_eq!(
				fs::symlink_metadata(scratch.path("job").join(name))
					.unwrap_err()
					.kind(),
				std::io::ErrorKind::NotFound
			);
		}
		let bytes: Vec<_> = (0_u8..=250).cycle().take(65_536).collect();
		let held = job.seal_job_record(record, &bytes, &gate).unwrap();
		let mut actual = vec![0; bytes.len()];
		held.read_exact_job_record(&job, &mut actual).unwrap();
		assert_eq!(actual, bytes);
		let prior_steps = gate.steps.borrow().clone();
		for length in [0, 65_535, 65_537] {
			let mut wrong = vec![0x37; length];
			assert!(matches!(
				held.read_exact_job_record(&job, &mut wrong),
				Err(StageError::InvalidLength)
			));
			assert!(wrong.iter().all(|byte| *byte == 0x37));
		}
		assert_eq!(*gate.steps.borrow(), prior_steps);
		assert_eq!(fs::read(scratch.path("job").join(name)).unwrap(), bytes);
	}
}

#[test]
fn private_record_sync_refusal_retains_written_bytes_without_a_usable_pin() {
	for (record, role, name) in [
		(ApplyJobRecord::Owner, ApplyRole::Owner, "owner.cbor"),
		(
			ApplyJobRecord::PrivatePlan,
			ApplyRole::PrivatePlan,
			"plan.cbor",
		),
	] {
		let scratch = Scratch::new();
		let root = DestinationRoot::from_directory(scratch.open()).unwrap();
		let gate = FixtureAdmission::default();
		let job = root
			.create_job_admitted(UnixComponent::new(b"job").unwrap(), &gate)
			.unwrap();
		gate.steps.borrow_mut().clear();
		gate.refuse.set(Some(ApplyStep::Sync(role)));
		assert!(matches!(
			job.seal_job_record(record, b"retained", &gate),
			Err(StageError::Admission(_))
		));
		let path = scratch.path("job").join(name);
		let retained = fs::symlink_metadata(&path).unwrap();
		assert_eq!(retained.mode() & 0o7777, 0o600);
		assert_eq!(retained.nlink(), 1);
		assert_eq!(fs::read(&path).unwrap(), b"retained");
		{
			let steps = gate.steps.borrow();
			assert!(steps.len() >= 3);
			assert_eq!(steps.first(), Some(&ApplyStep::Create(role)));
			assert_eq!(steps.last(), Some(&ApplyStep::Sync(role)));
			assert!(
				steps[1..steps.len() - 1]
					.iter()
					.all(|step| *step == ApplyStep::Write(role, 0, 8))
			);
		}
		gate.refuse.set(None);
		assert!(matches!(
			job.seal_job_record(record, b"replaced", &gate),
			Err(StageError::AlreadyExists)
		));
		let after = fs::symlink_metadata(&path).unwrap();
		assert_eq!((after.dev(), after.ino()), (retained.dev(), retained.ino()));
		assert_eq!(fs::read(path).unwrap(), b"retained");
	}
}

#[test]
fn held_record_cannot_be_read_against_another_job_with_identical_artifacts() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let gate = FixtureAdmission::default();
	let first = root
		.create_job_admitted(UnixComponent::new(b"first").unwrap(), &gate)
		.unwrap();
	let second = root
		.create_job_admitted(UnixComponent::new(b"second").unwrap(), &gate)
		.unwrap();
	let held = first
		.seal_job_record(ApplyJobRecord::Owner, b"same", &gate)
		.unwrap();
	let other = second
		.seal_job_record(ApplyJobRecord::Owner, b"same", &gate)
		.unwrap();
	let mut bytes = [0x57; 4];
	assert!(matches!(
		held.read_exact_job_record(&second, &mut bytes),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(bytes, [0x57; 4]);
	held.read_exact_job_record(&first, &mut bytes).unwrap();
	assert_eq!(&bytes, b"same");
	bytes.fill(0x57);
	other.read_exact_job_record(&second, &mut bytes).unwrap();
	assert_eq!(&bytes, b"same");
	assert_eq!(fs::read(scratch.path("first/owner.cbor")).unwrap(), b"same");
	assert_eq!(
		fs::read(scratch.path("second/owner.cbor")).unwrap(),
		b"same"
	);
}
