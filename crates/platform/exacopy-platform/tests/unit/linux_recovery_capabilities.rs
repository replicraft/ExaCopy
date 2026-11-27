use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_recovery::{RecoveryInventoryView, RecoveryJobView, RecoveryRecord};
use exacopy_endpoint::{ReadView, UnixComponent};

use crate::linux::job::{
	CHECKPOINTS, FIRST_SEGMENT, JOURNAL, OWNER, PLAN, STAGE, checkpoint_page_name,
};
use crate::linux::{DestinationRoot, ExtendedAttributes, ReadError, StageError};
use crate::scratch::Scratch;

const JOB: &str = "capability-job";
const PART: &str = "capability-part";
const TARGET: &str = "capability-target";
const CHECKPOINT_ORDINAL: u32 = 1;
const PERMISSION_BITS: u32 = 0o777;
const OWNER_BYTES: &[u8] = b"fixture owner";
const PLAN_BYTES: &[u8] = b"fixture plan";
const JOURNAL_BYTES: &[u8] = b"fixture segment";
const CHECKPOINT_BYTES: &[u8] = b"fixture checkpoint page";
const STAGE_BYTES: &[u8] = b"fixture stage";
const TARGET_BYTES: &[u8] = b"fixture incumbent";
const APPENDED_BYTES: &[u8] = b" appended";

#[test]
fn recovery_job_view_reopens_distinct_read_only_artifacts() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let job_name = component(JOB);
	let writer = root.create_job_directory(job_name).unwrap();
	writer
		.create_owner_record()
		.unwrap()
		.write_all(OWNER_BYTES)
		.unwrap();
	writer
		.create_plan_record()
		.unwrap()
		.write_all(PLAN_BYTES)
		.unwrap();
	writer
		.create_journal_directory()
		.unwrap()
		.create_first_segment()
		.unwrap()
		.write_all(JOURNAL_BYTES)
		.unwrap();
	writer
		.create_checkpoint_directory()
		.unwrap()
		.write_page(CHECKPOINT_ORDINAL, CHECKPOINT_BYTES)
		.unwrap();
	drop(writer);

	let job = root.open_recovery_job(job_name).unwrap();
	let _lease = job.try_read_lease().unwrap();
	assert_artifact_view(&job, &fixture.path(JOB), &fixture.path(""));
}

fn assert_artifact_view(
	job: &impl RecoveryJobView<ReadError = ReadError, NamespaceError = StageError>,
	job_path: &Path,
	root_path: &Path,
) {
	assert_eq!(job.identities(), (identity(job_path), identity(root_path)));
	for (mut record, path, bytes) in [
		(job.open_owner().unwrap(), job_path.join(OWNER), OWNER_BYTES),
		(job.open_plan().unwrap(), job_path.join(PLAN), PLAN_BYTES),
		(
			job.open_first_segment().unwrap(),
			job_path.join(JOURNAL).join(FIRST_SEGMENT),
			JOURNAL_BYTES,
		),
		(
			job.open_checkpoint(CHECKPOINT_ORDINAL).unwrap(),
			job_path
				.join(CHECKPOINTS)
				.join(checkpoint_page_name(CHECKPOINT_ORDINAL).unwrap()),
			CHECKPOINT_BYTES,
		),
	] {
		let record_identity: JobFileIdentity = record.identity().into();
		assert_eq!(record_identity, identity(&path));
		assert_record(&record, bytes);
		let mut sequential = vec![0; bytes.len()];
		std::io::Read::read_exact(&mut record, &mut sequential).unwrap();
		assert_eq!(sequential, bytes);
		assert_eq!(fs::read(&path).unwrap(), bytes);
	}
}

#[test]
fn recovery_record_view_reports_extra_data_at_the_captured_extent() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let job_name = component(JOB);
	let writer = root.create_job_directory(job_name).unwrap();
	writer
		.create_owner_record()
		.unwrap()
		.write_all(OWNER_BYTES)
		.unwrap();
	drop(writer);

	let job = root.open_recovery_job(job_name).unwrap();
	let mut record = RecoveryJobView::open_owner(&job).unwrap();
	assert_record(&record, OWNER_BYTES);
	let owner_path = fixture.path(JOB).join(OWNER);
	let metadata = fs::metadata(&owner_path).unwrap();
	let captured = RecoveryRecord::observation(&record);
	assert_eq!(
		captured.mode,
		metadata.permissions().mode() & PERMISSION_BITS
	);
	assert_eq!(captured.owner, metadata.uid());
	assert_eq!(captured.group, metadata.gid());
	assert_eq!(captured.links, metadata.nlink());
	assert_eq!(captured.modified_at.seconds, metadata.mtime());
	assert_eq!(
		captured.modified_at.nanoseconds,
		u32::try_from(metadata.mtime_nsec()).unwrap()
	);
	assert_ne!(
		RecoveryRecord::extended_attributes(&record).unwrap(),
		ExtendedAttributes::Present
	);

	// Change only the disposable fixture while the adapter holds its read-only view.
	OpenOptions::new()
		.append(true)
		.open(&owner_path)
		.unwrap()
		.write_all(APPENDED_BYTES)
		.unwrap();
	assert!(matches!(
		RecoveryRecord::recheck_inode(&record),
		Err(ReadError::SourceChanged)
	));
	assert!(matches!(
		ReadView::recheck_observation(&record),
		Err(ReadError::UnexpectedDataAfterEnd)
	));
	assert!(matches!(
		RecoveryRecord::check_logical_eof(&record),
		Err(ReadError::UnexpectedDataAfterEnd)
	));
	assert!(matches!(
		ReadView::read_exact_at(&record, ReadView::length(&record), &mut [0]),
		Err(ReadError::RangeOutsideFile)
	));
	let mut sequential = [0; OWNER_BYTES.len()];
	std::io::Read::read_exact(&mut record, &mut sequential).unwrap();
	assert_eq!(sequential, OWNER_BYTES);
	assert_eq!(
		fs::read(&owner_path).unwrap(),
		[OWNER_BYTES, APPENDED_BYTES].concat()
	);
}

#[test]
fn recovery_inventory_view_preserves_both_names_and_refuses_a_stale_absence() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let job_name = component(JOB);
	let writer = root.create_job_directory(job_name).unwrap();
	writer.create_stage_directory().unwrap();
	drop(writer);

	let stage_directory = fixture.path(JOB).join(STAGE);
	let stage_path = stage_directory.join(PART);
	fs::write(&stage_path, STAGE_BYTES).unwrap();
	let target_path = fixture.path(TARGET);
	let job = root.open_recovery_job(job_name).unwrap();
	let _lease = job.try_read_lease().unwrap();

	let part = component(PART);
	let target = component(TARGET);
	let first = RecoveryJobView::inventory(&job, part, target).unwrap();
	assert_eq!(
		RecoveryInventoryView::stage_directory_identity(&first),
		Some(identity(&stage_directory))
	);
	let initial_stage = RecoveryInventoryView::stage(&first).unwrap();
	let original_stage_identity = identity(&stage_path);
	assert_eq!(
		JobFileIdentity::from(RecoveryRecord::identity(initial_stage)),
		original_stage_identity
	);
	assert_record(initial_stage, STAGE_BYTES);
	assert!(RecoveryInventoryView::target(&first).is_none());
	RecoveryInventoryView::recheck(&first).unwrap();

	fs::write(&target_path, TARGET_BYTES).unwrap();
	assert!(matches!(
		RecoveryInventoryView::recheck(&first),
		Err(StageError::IdentityChanged)
	));
	let second = RecoveryJobView::inventory(&job, part, target).unwrap();
	let stage = RecoveryInventoryView::stage(&second).unwrap();
	let incumbent = RecoveryInventoryView::target(&second).unwrap();
	assert_record(stage, STAGE_BYTES);
	assert_record(incumbent, TARGET_BYTES);
	assert_eq!(
		JobFileIdentity::from(RecoveryRecord::identity(stage)),
		original_stage_identity
	);
	assert_eq!(identity(&stage_path), original_stage_identity);
	assert_eq!(
		JobFileIdentity::from(RecoveryRecord::identity(incumbent)),
		identity(&target_path)
	);
	RecoveryInventoryView::recheck(&second).unwrap();
	assert_eq!(fs::read(&stage_path).unwrap(), STAGE_BYTES);
	assert_eq!(fs::read(&target_path).unwrap(), TARGET_BYTES);
}

fn assert_record(record: &impl RecoveryRecord<Error = ReadError>, bytes: &[u8]) {
	assert_eq!(record.length(), u64::try_from(bytes.len()).unwrap());
	let mut buffer = vec![0; bytes.len()];
	record.read_exact_at(0, &mut buffer).unwrap();
	assert_eq!(buffer, bytes);
	record.check_logical_eof().unwrap();
	record.recheck_observation().unwrap();
}

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).unwrap()
}

fn identity(path: &Path) -> JobFileIdentity {
	let metadata = fs::metadata(path).unwrap();
	JobFileIdentity {
		device: metadata.dev(),
		inode: metadata.ino(),
	}
}
