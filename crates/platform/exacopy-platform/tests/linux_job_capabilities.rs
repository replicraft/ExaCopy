//! Native Linux conformance checks for the held job bootstrap capabilities.

#![cfg(target_os = "linux")]

mod common;

use std::fs::{self, Metadata};
use std::io::Write;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use exacopy_endpoint::linux_job::{
	JobBootstrapRoot, JobFileIdentity, JobJournalDirectory, JobRecord, JobWorkspace,
};
use exacopy_endpoint::{JournalSegment, UnixComponent};
use exacopy_platform::linux::{DestinationRoot, StageError};

use common::Scratch;

const JOB: &str = "fixture-job";
const OWNER: &str = "owner.cbor";
const PLAN: &str = "plan.cbor";
const JOURNAL: &str = "journal";
const FIRST_SEGMENT: &str = "00000000000000000001.exajnl";
const OWNER_BYTES: &[u8] = b"synthetic owner record";
const PLAN_BYTES: &[u8] = b"distinct synthetic plan record";
const SEGMENT_BYTES: &[u8] = b"synthetic segment payload";
const MODE_BITS: u32 = 0o7777;
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

fn identity(metadata: &Metadata) -> JobFileIdentity {
	JobFileIdentity {
		device: metadata.dev(),
		inode: metadata.ino(),
	}
}

fn write_record(mut record: impl JobRecord, bytes: &[u8]) {
	Write::write_all(&mut record, bytes).expect("write the private record");
	Write::flush(&mut record).expect("flush the private record writer");
	JobRecord::sync_all(&record).expect("synchronize the private record");
}

fn private_directory(path: &Path) -> JobFileIdentity {
	let metadata = fs::symlink_metadata(path).expect("inspect the private directory");
	assert!(metadata.is_dir(), "expected a directory at {path:?}");
	assert_eq!(
		metadata.mode() & MODE_BITS,
		PRIVATE_DIRECTORY_MODE,
		"directory permissions at {path:?}"
	);
	identity(&metadata)
}

fn private_file(path: &Path, bytes: &[u8]) -> JobFileIdentity {
	let metadata = fs::symlink_metadata(path).expect("inspect the private file");
	assert!(metadata.is_file(), "expected a regular file at {path:?}");
	assert_eq!(
		metadata.mode() & MODE_BITS,
		PRIVATE_FILE_MODE,
		"file permissions at {path:?}"
	);
	assert_eq!(
		fs::read(path).expect("read the private file independently"),
		bytes,
		"file bytes at {path:?}"
	);
	identity(&metadata)
}

fn assert_collision<T>(result: Result<T, StageError>, name: &str) {
	assert!(
		matches!(result, Err(StageError::AlreadyExists)),
		"exclusive creation at {name} should report a collision"
	);
}

#[test]
fn held_job_capabilities_create_and_preserve_private_bootstrap_entries() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).expect("admit the fixture root");
	let root_metadata = scratch.open().metadata().expect("inspect the fixture root");
	assert_eq!(JobBootstrapRoot::identity(&root), identity(&root_metadata));

	let name = UnixComponent::new(JOB.as_bytes()).expect("validate the fixture job name");
	let job = JobBootstrapRoot::create_job_directory(&root, name).expect("create the job");
	scratch.assert_debug_redacts(&job, &[JOB]);
	let job_path = scratch.path(JOB);
	let job_identity = private_directory(&job_path);
	assert_eq!(JobWorkspace::identity(&job), job_identity);

	write_record(
		JobWorkspace::create_owner_record(&job).expect("create the owner record"),
		OWNER_BYTES,
	);
	write_record(
		JobWorkspace::create_plan_record(&job).expect("create the plan record"),
		PLAN_BYTES,
	);
	let journal = JobWorkspace::create_journal_directory(&job).expect("create the journal");
	let mut segment =
		JobJournalDirectory::create_first_segment(&journal).expect("create the first segment");
	Write::write_all(&mut segment, SEGMENT_BYTES).expect("write the synthetic segment payload");
	JournalSegment::sync(&segment).expect("synchronize the segment");
	JobJournalDirectory::sync_directory(&journal).expect("synchronize the journal");
	JobWorkspace::sync_directory(&job).expect("synchronize the job directory");
	JobBootstrapRoot::sync_directory(&root).expect("synchronize the destination root");

	let owner_path = job_path.join(OWNER);
	let plan_path = job_path.join(PLAN);
	let journal_path = job_path.join(JOURNAL);
	let segment_path = journal_path.join(FIRST_SEGMENT);
	let owner_identity = private_file(&owner_path, OWNER_BYTES);
	let plan_identity = private_file(&plan_path, PLAN_BYTES);
	let journal_identity = private_directory(&journal_path);
	let segment_identity = private_file(&segment_path, SEGMENT_BYTES);

	assert_collision(JobBootstrapRoot::create_job_directory(&root, name), JOB);
	assert_collision(JobWorkspace::create_owner_record(&job), OWNER);
	assert_collision(JobWorkspace::create_plan_record(&job), PLAN);
	assert_collision(JobWorkspace::create_journal_directory(&job), JOURNAL);
	assert_collision(
		JobJournalDirectory::create_first_segment(&journal),
		FIRST_SEGMENT,
	);

	assert_eq!(private_directory(&job_path), job_identity);
	assert_eq!(private_file(&owner_path, OWNER_BYTES), owner_identity);
	assert_eq!(private_file(&plan_path, PLAN_BYTES), plan_identity);
	assert_eq!(private_directory(&journal_path), journal_identity);
	assert_eq!(private_file(&segment_path, SEGMENT_BYTES), segment_identity);
}
