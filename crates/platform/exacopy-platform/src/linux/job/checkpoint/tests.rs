use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, symlink};
use std::path::Path;

use exacopy_endpoint::UnixComponent;

use crate::linux::{DestinationRoot, StageError};
use crate::scratch::Scratch;

const JOB: &str = "private-job";
const CHECKPOINTS: &str = "checkpoints";
const FIRST_PAGE: &str = "range-0000000001.cbor";
const LAST_ORDINAL: u32 = 4_096;
const MAX_LENGTH: usize = 95;
const DATA: [u8; MAX_LENGTH] = [0xa7; MAX_LENGTH];

#[test]
fn page_creation_is_exclusive_and_checked_recovery_reads_the_original() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination");
	let job = root.create_job_directory(job_name()).expect("private job");
	let checkpoints = job
		.create_checkpoint_directory()
		.expect("private checkpoints");
	job.sync_directory()
		.expect("persist checkpoint directory name");
	assert!(matches!(
		job.create_checkpoint_directory(),
		Err(StageError::AlreadyExists)
	));
	checkpoints
		.write_page(1, &DATA)
		.expect("persist checkpoint page");
	checkpoints
		.write_page(LAST_ORDINAL, &[0x55])
		.expect("persist last allowed checkpoint page");
	assert!(matches!(
		checkpoints.write_page(1, &[0]),
		Err(StageError::AlreadyExists)
	));
	let directory = fixture.path(JOB).join(CHECKPOINTS);
	let directory_metadata = fs::metadata(&directory).expect("checkpoint directory metadata");
	assert_eq!(directory_metadata.mode() & 0o7777, 0o700);
	let page_path = directory.join(FIRST_PAGE);
	let page_metadata = fs::metadata(&page_path).expect("checkpoint page metadata");
	assert_eq!(page_metadata.mode() & 0o7777, 0o600);
	assert_eq!(page_metadata.nlink(), 1);
	fixture.assert_debug_redacts(&checkpoints, &[JOB, CHECKPOINTS]);
	drop(job);

	let recovery = root
		.open_recovery_job(job_name())
		.expect("held recovery job");
	let _lease = recovery.try_read_lease().expect("shared job lease");
	let page = recovery.open_checkpoint_page(1).expect("checked page");
	let mut contents = [0; MAX_LENGTH];
	page.read_exact_at(0, &mut contents)
		.expect("read checkpoint data");
	page.check_logical_eof().expect("no bytes beyond the page");
	page.recheck_observation().expect("page inode observation");
	assert_eq!(contents, DATA);
	assert_eq!(page.identity().inode(), page_metadata.ino());
	let mut last = [0];
	recovery
		.open_checkpoint_page(LAST_ORDINAL)
		.expect("last page")
		.read_exact_at(0, &mut last)
		.expect("read last page contents");
	assert_eq!(last, [0x55]);
}

#[test]
fn invalid_page_bounds_leave_no_new_files_and_block_recovery() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination");
	let job = root.create_job_directory(job_name()).expect("private job");
	let checkpoints = job
		.create_checkpoint_directory()
		.expect("private checkpoints");
	let invalid_ordinals = [0, LAST_ORDINAL + 1, u32::MAX];
	for ordinal in invalid_ordinals {
		assert!(matches!(
			checkpoints.write_page(ordinal, &DATA),
			Err(StageError::InvalidCheckpointOrdinal)
		));
	}
	let oversized = [0; MAX_LENGTH + 1];
	let invalid_lengths = [&[][..], &oversized];
	for bytes in invalid_lengths {
		assert!(matches!(
			checkpoints.write_page(1, bytes),
			Err(StageError::InvalidCheckpointPageLength)
		));
	}
	let directory = fixture.path(JOB).join(CHECKPOINTS);
	assert_eq!(
		fs::read_dir(&directory)
			.expect("checkpoint entries")
			.count(),
		0
	);
	drop(job);

	let recovery = root
		.open_recovery_job(job_name())
		.expect("held recovery job");
	let _lease = recovery.try_read_lease().expect("shared job lease");
	for ordinal in invalid_ordinals {
		assert!(matches!(
			recovery.open_checkpoint_page(ordinal),
			Err(StageError::InvalidCheckpointOrdinal)
		));
	}
	let path = directory.join(FIRST_PAGE);
	for bytes in invalid_lengths {
		write_private_fixture(&path, bytes);
		assert!(matches!(
			recovery.open_checkpoint_page(1),
			Err(StageError::InvalidCheckpointPageLength)
		));
		fs::remove_file(&path).expect("reset fixture");
	}
}

#[test]
fn checkpoint_pages_reject_symbolic_and_hard_links() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination");
	let job = root.create_job_directory(job_name()).expect("private job");
	let checkpoints = job
		.create_checkpoint_directory()
		.expect("private checkpoints");
	let page = fixture.path(JOB).join(CHECKPOINTS).join(FIRST_PAGE);
	let incumbent = fixture.path("incumbent");
	write_private_fixture(&incumbent, &DATA);
	symlink(&incumbent, &page).expect("symlink fixture");
	assert!(matches!(
		checkpoints.write_page(1, &[0]),
		Err(StageError::AlreadyExists)
	));
	assert!(page.is_symlink());
	drop(job);

	let recovery = root
		.open_recovery_job(job_name())
		.expect("held recovery job");
	let _lease = recovery.try_read_lease().expect("shared job lease");
	assert!(recovery.open_checkpoint_page(1).is_err());
	fs::remove_file(&page).expect("reset symlink fixture");
	fs::hard_link(&incumbent, &page).expect("hard-link fixture");
	assert!(matches!(
		recovery.open_checkpoint_page(1),
		Err(StageError::UnsafeFile)
	));
	assert_eq!(fs::read(incumbent).expect("incumbent contents"), DATA);
}

#[test]
fn displaced_checkpoint_directory_cannot_write_and_recovery_refuses_symlinks() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination");
	let job = root.create_job_directory(job_name()).expect("private job");
	let checkpoints = job
		.create_checkpoint_directory()
		.expect("private checkpoints");
	let directory = fixture.path(JOB).join(CHECKPOINTS);
	let displaced = fixture.path("displaced-checkpoints");
	fs::rename(&directory, &displaced).expect("move original directory");
	let _replacement = job
		.create_checkpoint_directory()
		.expect("replacement checkpoints");
	assert!(matches!(
		checkpoints.write_page(1, &DATA),
		Err(StageError::IdentityChanged)
	));
	assert!(!directory.join(FIRST_PAGE).exists());
	assert!(!displaced.join(FIRST_PAGE).exists());
	fs::remove_dir(&directory).expect("remove empty replacement");
	symlink(&displaced, &directory).expect("symlink fixture");
	write_private_fixture(&displaced.join(FIRST_PAGE), &DATA);
	assert!(checkpoints.write_page(1, &[0]).is_err());
	drop(job);

	let recovery = root
		.open_recovery_job(job_name())
		.expect("held recovery job");
	let _lease = recovery.try_read_lease().expect("shared job lease");
	assert!(recovery.open_checkpoint_page(1).is_err());
	assert_eq!(
		fs::read(displaced.join(FIRST_PAGE)).expect("displaced page"),
		DATA
	);
}

#[test]
fn held_writer_and_recovery_refuse_a_rebound_job() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination");
	let job = root.create_job_directory(job_name()).expect("private job");
	let checkpoints = job
		.create_checkpoint_directory()
		.expect("private checkpoints");
	let recovery = root
		.open_recovery_job(job_name())
		.expect("held recovery job");
	let displaced = fixture.path("displaced-job");
	fs::rename(fixture.path(JOB), &displaced).expect("rebind private job");
	let replacement = root
		.create_job_directory(job_name())
		.expect("replacement job");
	let new_checkpoints = replacement
		.create_checkpoint_directory()
		.expect("replacement checkpoints");
	new_checkpoints.write_page(1, &[0]).expect("new job page");
	assert!(matches!(
		checkpoints.write_page(1, &DATA),
		Err(StageError::IdentityChanged)
	));
	assert!(matches!(
		recovery.open_checkpoint_page(1),
		Err(StageError::IdentityChanged)
	));
	assert!(!displaced.join(CHECKPOINTS).join(FIRST_PAGE).exists());
}

fn job_name() -> UnixComponent<'static> {
	UnixComponent::new(JOB.as_bytes()).expect("fixture job component")
}

fn write_private_fixture(path: &Path, bytes: &[u8]) {
	OpenOptions::new()
		.create_new(true)
		.write(true)
		.mode(0o600)
		.open(path)
		.expect("private fixture record")
		.write_all(bytes)
		.expect("write fixture record");
}
