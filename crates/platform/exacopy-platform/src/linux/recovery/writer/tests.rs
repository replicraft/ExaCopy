use std::fs;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::symlink;

use exacopy_endpoint::{JournalSegment, UnixComponent};
use rustix::fs::{OFlags, fcntl_getfl};

use super::{FIRST_SEGMENT, JOURNAL, RECEIPT, RECEIPTS};
use crate::linux::{DestinationRoot, LinuxJournalSegment, StageError};
use crate::scratch::Scratch;

const JOB: &str = "recovery-writer-job";
const STAGE_DIRECTORY: &str = "stage";
const PART: &str = "private-stage-file";
const TARGET: &str = "public-target";
const MOVED: &str = "moved-inode";

#[test]
fn exclusive_lease_conflicts_until_drop_and_refuses_replacement_job() {
	let (scratch, root) = fixture();
	let live = root.create_job_directory(name(JOB)).unwrap();
	let read_job = root.open_recovery_job(name(JOB)).unwrap();
	let expected = read_job.identity();
	assert!(matches!(
		root.try_recovery_write_lease(name(JOB), expected),
		Err(StageError::JobBusy)
	));
	drop(live);

	let read = read_job.try_read_lease().unwrap();
	assert!(matches!(
		root.try_recovery_write_lease(name(JOB), expected),
		Err(StageError::JobBusy)
	));
	drop(read);

	let exclusive = root.try_recovery_write_lease(name(JOB), expected).unwrap();
	assert_eq!(exclusive.job().identity(), expected);
	assert!(matches!(
		read_job.try_read_lease(),
		Err(StageError::JobBusy)
	));
	assert!(matches!(
		root.try_recovery_write_lease(name(JOB), expected),
		Err(StageError::JobBusy)
	));
	drop(exclusive);

	let _read = read_job.try_read_lease().unwrap();
	fs::rename(scratch.path(JOB), scratch.path(MOVED)).unwrap();
	let replacement = root.create_job_directory(name(JOB)).unwrap();
	assert_ne!(replacement.identity(), expected);
	assert!(matches!(
		root.try_recovery_write_lease(name(JOB), expected),
		Err(StageError::IdentityChanged)
	));
}

#[test]
fn only_the_exact_private_journal_inode_reopens_for_append() {
	let (scratch, root) = fixture();
	let mut initial = bootstrap_segment(&root);
	initial.write_all(b"initial prefix").unwrap();
	drop(initial);
	let inspection = root.open_recovery_job(name(JOB)).unwrap();
	let writer = root
		.try_recovery_write_lease(name(JOB), inspection.identity())
		.unwrap();
	let segment = writer.job().open_first_segment().unwrap();
	let opened = writer.open_first_segment_for_append(&segment).unwrap();
	assert!(matches!(
		writer.open_first_segment_for_append(&segment),
		Err(StageError::JobBusy)
	));
	drop(opened);
	let mut append = writer.open_first_segment_for_append(&segment).unwrap();
	assert_eq!(append.stream_position().unwrap(), segment.len());
	let flags = append.flags().unwrap();
	assert_eq!(flags & OFlags::ACCMODE, OFlags::RDWR);
	assert!(flags.contains(OFlags::APPEND | OFlags::NOATIME));
	// Moving the cursor for rescans never converts the descriptor to overwrite mode.
	append.seek(SeekFrom::Start(0)).unwrap();
	append.write_all(b" and suffix").unwrap();
	append.sync().unwrap();
	drop(append);

	let segment_path = scratch.path(JOB).join(JOURNAL).join(FIRST_SEGMENT);
	assert_eq!(
		fs::read(&segment_path).unwrap(),
		b"initial prefix and suffix"
	);
	assert!(writer.open_first_segment_for_append(&segment).is_err());
	let current = writer.job().open_first_segment().unwrap();
	let parked = scratch.path(MOVED);
	fs::rename(&segment_path, &parked).unwrap();
	symlink(&parked, &segment_path).unwrap();
	assert!(writer.open_first_segment_for_append(&current).is_err());

	fs::remove_file(&segment_path).unwrap();
	fs::hard_link(&parked, &segment_path).unwrap();
	assert!(matches!(
		writer.open_first_segment_for_append(&current),
		Err(StageError::UnsafeFile)
	));
	assert_eq!(fs::read(&parked).unwrap(), b"initial prefix and suffix");
}

#[test]
fn publication_barriers_require_the_leased_job_and_current_published_names() {
	let (scratch, root) = fixture();
	let bootstrap = root.create_job_directory(name(JOB)).unwrap();
	bootstrap.create_stage_directory().unwrap();
	drop(bootstrap);
	let directory = scratch.path(JOB).join(STAGE_DIRECTORY);
	let private_path = directory.join(PART);
	let target_path = scratch.path(TARGET);
	fs::write(&private_path, b"sealed bytes").unwrap();

	let inspection = root.open_recovery_job(name(JOB)).unwrap();
	let writer = root
		.try_recovery_write_lease(name(JOB), inspection.identity())
		.unwrap();
	let job = writer.job();
	let staged = job.inventory(name(PART), name(TARGET)).unwrap();
	assert!(matches!(
		writer.sync_publication(&staged),
		Err(StageError::IdentityChanged)
	));

	fs::rename(&private_path, &target_path).unwrap();
	let separate = inspection.inventory(name(PART), name(TARGET)).unwrap();
	assert!(matches!(
		writer.sync_publication(&separate),
		Err(StageError::IdentityChanged)
	));
	let published = job.inventory(name(PART), name(TARGET)).unwrap();
	writer.sync_publication(&published).unwrap();
	assert_eq!(fs::read(&target_path).unwrap(), b"sealed bytes");

	fs::rename(&target_path, scratch.path(MOVED)).unwrap();
	fs::write(&target_path, b"later incumbent").unwrap();
	assert!(matches!(
		writer.sync_publication(&published),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(fs::read(&target_path).unwrap(), b"later incumbent");
}

#[test]
fn receipts_are_exclusive_and_existing_bytes_have_only_read_access() {
	let (scratch, root) = fixture();
	let bootstrap = root.create_job_directory(name(JOB)).unwrap();
	let identity = bootstrap.identity();
	drop(bootstrap);

	let writer = root.try_recovery_write_lease(name(JOB), identity).unwrap();
	let receipts = writer.open_receipt_directory().unwrap();
	assert!(receipts.open_receipt().unwrap().is_none());
	let mut new = receipts.create_receipt().unwrap();
	new.write_all(b"existing receipt").unwrap();
	drop(new);

	let reopened = writer.open_receipt_directory().unwrap();
	let receipt = reopened.open_receipt().unwrap().unwrap();
	assert_eq!(
		fcntl_getfl(&receipt.file).unwrap() & OFlags::ACCMODE,
		OFlags::RDONLY
	);
	reopened.sync_receipt(&receipt).unwrap();
	reopened.sync_directory().unwrap();
	writer.sync_job_directory().unwrap();
	assert!(matches!(
		reopened.create_receipt(),
		Err(StageError::AlreadyExists)
	));
	let directory = scratch.path(JOB).join(RECEIPTS);
	let receipt_path = directory.join(RECEIPT);
	assert_eq!(fs::read(&receipt_path).unwrap(), b"existing receipt");

	fs::rename(&receipt_path, scratch.path(MOVED)).unwrap();
	symlink(scratch.path(MOVED), &receipt_path).unwrap();
	assert!(matches!(
		reopened.open_receipt(),
		Err(StageError::UnsafeFile)
	));
	assert!(reopened.sync_receipt(&receipt).is_err());
	assert!(matches!(
		reopened.create_receipt(),
		Err(StageError::AlreadyExists)
	));
	assert_eq!(fs::read(scratch.path(MOVED)).unwrap(), b"existing receipt");
}

fn fixture() -> (Scratch, DestinationRoot) {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).expect("managed fixture root");
	(scratch, root)
}

fn name(component: &str) -> UnixComponent<'_> {
	UnixComponent::new(component.as_bytes()).expect("valid fixture component")
}

fn bootstrap_segment(root: &DestinationRoot) -> LinuxJournalSegment<'static> {
	let job = root.create_job_directory(name(JOB)).unwrap();
	let journal = job.create_journal_directory().unwrap();
	journal.create_first_segment().unwrap()
}

#[test]
fn fresh_segment_keeps_the_original_open_description_locked() {
	let (_scratch, root) = fixture();
	// The bootstrap job and its journal directory have already been dropped.
	let writer = bootstrap_segment(&root);
	let job = root.open_recovery_job(name(JOB)).unwrap();
	assert!(matches!(
		root.try_recovery_write_lease(name(JOB), job.identity()),
		Err(StageError::JobBusy)
	));
	assert!(matches!(job.try_read_lease(), Err(StageError::JobBusy)));
	drop(writer);
	assert!(
		root.try_recovery_write_lease(name(JOB), job.identity())
			.is_ok()
	);
}
