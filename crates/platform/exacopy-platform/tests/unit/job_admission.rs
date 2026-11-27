use std::error::Error as _;
use std::fs;
use std::io::{self, Write as _};
use std::os::unix::fs::PermissionsExt as _;

use exacopy_endpoint::UnixComponent;
use rustix::io::Errno;

use super::{
	DestinationRoot, DirectoryCreateFailure, FIRST_SEGMENT, JOURNAL, JobDirectoryCreationError,
	OWNER, STAGE, StageError,
};
use crate::scratch::Scratch;

const JOB: &str = "job";
const OWNER_BYTES: &[u8] = b"synthetic private owner record";
const SEGMENT_BYTES: &[u8] = b"private segment fixture";
const PRIVATE_MODE: u32 = 0o700;
const NON_PRIVATE_MODE: u32 = 0o750;

fn refuse() -> io::Result<()> {
	Err(io::ErrorKind::PermissionDenied.into())
}

fn must_not_enter() -> io::Result<()> {
	panic!("invalidated directory reached admission");
}

#[test]
fn refusal_before_creation_preserves_absence_and_incumbent_owner_bytes() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).expect("held destination");
	let selected = UnixComponent::new(JOB.as_bytes()).expect("job component");
	let job_path = scratch.path(JOB);
	assert!(matches!(
		root.create_job_directory_admitted(selected, refuse),
		Err(JobDirectoryCreationError::NotCreated(StageError::Admission(cause)))
			if cause.kind() == io::ErrorKind::PermissionDenied
	));
	assert_absent(&job_path);

	let job = root
		.create_job_directory(selected)
		.expect("ordinary local job");
	let owner_path = job_path.join(OWNER);
	assert!(matches!(
		job.write_owner_record_admitted(OWNER_BYTES, refuse),
		Err(StageError::Admission(cause)) if cause.kind() == io::ErrorKind::PermissionDenied
	));
	assert_absent(&owner_path);

	let mut owner = job
		.create_owner_record()
		.expect("create local owner fixture");
	owner
		.write_all(OWNER_BYTES)
		.expect("seed private owner bytes");
	drop(owner);
	assert!(matches!(
		job.write_owner_record_admitted(b"replacement", refuse),
		Err(StageError::Admission(cause)) if cause.kind() == io::ErrorKind::PermissionDenied
	));
	assert_eq!(
		fs::read(owner_path).expect("preserved owner bytes"),
		OWNER_BYTES
	);
}

#[test]
fn refusal_before_private_directory_and_segment_effects_preserves_the_namespace() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).expect("held destination");
	let selected = UnixComponent::new(JOB.as_bytes()).expect("job component");
	let job = root
		.create_job_directory(selected)
		.expect("ordinary local job");
	let job_path = scratch.path(JOB);
	let journal_path = job_path.join(JOURNAL);
	let segment_path = journal_path.join(FIRST_SEGMENT);
	assert!(matches!(
		job.create_stage_directory_admitted(refuse),
		Err(StageError::Admission(cause)) if cause.kind() == io::ErrorKind::PermissionDenied
	));
	assert_absent(&job_path.join(STAGE));
	assert!(matches!(
		job.create_journal_directory_admitted(refuse),
		Err(StageError::Admission(cause)) if cause.kind() == io::ErrorKind::PermissionDenied
	));
	assert_absent(&journal_path);

	let journal = job
		.create_journal_directory()
		.expect("ordinary local journal");
	assert!(matches!(
		journal.create_first_segment_admitted(refuse),
		Err(StageError::Admission(cause)) if cause.kind() == io::ErrorKind::PermissionDenied
	));
	assert_absent(&segment_path);
	let mut segment = journal
		.create_first_segment()
		.expect("create local segment fixture");
	segment
		.write_all(SEGMENT_BYTES)
		.expect("seed segment bytes");
	assert!(matches!(
		journal.sync_directory_admitted(refuse),
		Err(StageError::Admission(cause)) if cause.kind() == io::ErrorKind::PermissionDenied
	));
	assert!(matches!(
		job.sync_directory_admitted(refuse),
		Err(StageError::Admission(cause)) if cause.kind() == io::ErrorKind::PermissionDenied
	));
	assert_eq!(
		fs::read(segment_path).expect("preserved segment"),
		SEGMENT_BYTES
	);
}

#[test]
fn lost_directory_privacy_refuses_before_requesting_an_effect_grant() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).expect("held destination");
	let selected = UnixComponent::new(JOB.as_bytes()).expect("job component");
	let job = root
		.create_job_directory(selected)
		.expect("ordinary local job");
	let job_path = scratch.path(JOB);
	let journal_path = job_path.join(JOURNAL);

	fs::set_permissions(&job_path, fs::Permissions::from_mode(NON_PRIVATE_MODE))
		.expect("change only the synthetic job mode");
	assert!(matches!(
		job.write_owner_record_admitted(OWNER_BYTES, must_not_enter),
		Err(StageError::UnsafeDirectory)
	));
	assert!(matches!(
		job.create_stage_directory_admitted(must_not_enter),
		Err(StageError::UnsafeDirectory)
	));
	assert!(matches!(
		job.create_journal_directory_admitted(must_not_enter),
		Err(StageError::UnsafeDirectory)
	));
	assert_absent(&job_path.join(OWNER));
	assert_absent(&job_path.join(STAGE));
	assert_absent(&journal_path);

	fs::set_permissions(&job_path, fs::Permissions::from_mode(PRIVATE_MODE))
		.expect("restore the synthetic job mode");
	let journal = job
		.create_journal_directory()
		.expect("ordinary local journal");
	fs::set_permissions(&journal_path, fs::Permissions::from_mode(NON_PRIVATE_MODE))
		.expect("change only the synthetic journal mode");
	assert!(matches!(
		journal.sync_directory_admitted(must_not_enter),
		Err(StageError::UnsafeDirectory)
	));
	assert!(
		fs::metadata(journal_path)
			.expect("preserved journal directory")
			.is_dir()
	);
}

#[test]
fn creation_error_exposes_its_disposition_and_original_cause() {
	use JobDirectoryCreationError as Failure;

	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).expect("held destination");
	let selected = UnixComponent::new(JOB.as_bytes()).expect("job component");
	let rejected = root.job_creation_failure(
		selected,
		DirectoryCreateFailure::Syscall(Errno::NAMETOOLONG),
	);
	assert!(matches!(
		&rejected,
		Failure::NotCreated(StageError::System(cause))
			if cause.raw_os_error() == Some(Errno::NAMETOOLONG.raw_os_error())
	));

	for (failure, context, cause_text) in [
		(
			rejected,
			"job directory was not created",
			"staging syscall failed",
		),
		(
			Failure::OutcomeUncertain(StageError::System(io::Error::other("synthetic I/O"))),
			"job directory creation is uncertain",
			"staging syscall failed: synthetic I/O",
		),
		(
			Failure::CreatedUnconfirmed(StageError::JobBusy),
			"created job directory could not be confirmed",
			"the job is in use",
		),
	] {
		let cause = failure
			.source()
			.and_then(|error| error.downcast_ref::<StageError>())
			.expect("retain the original typed staging cause");
		assert!(
			cause.to_string().contains(cause_text),
			"unexpected cause: {cause}"
		);
		assert_eq!(failure.to_string(), format!("{context}: {cause}"));
	}
	assert_absent(&scratch.path(JOB));
}

fn assert_absent(path: &std::path::Path) {
	assert_eq!(
		fs::symlink_metadata(path)
			.expect_err("fixture name must remain absent")
			.kind(),
		io::ErrorKind::NotFound,
		"unexpected namespace entry at {path:?}"
	);
}
