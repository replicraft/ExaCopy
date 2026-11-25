use std::fs::{self, DirBuilder, File, FileTimes, OpenOptions, Permissions};
use std::io::{Read as _, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{
	DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink,
};
use std::path::Path;
use std::time::{Duration, SystemTime};

use exacopy_endpoint::UnixComponent;
use rustix::fs::{self as linux_fs, Mode, OFlags};

use super::{FIRST_SEGMENT, JOURNAL, OWNER, PLAN, RECEIPT, RECEIPTS, STAGE};
use crate::linux::{DestinationRoot, ReadError, RecoveryFile, StageError};
use crate::scratch::Scratch;

const JOB: &str = "private-fixture-job";
const PARKED: &str = "detached-original";
const TARGET: &str = "public-fixture-name";
const PAYLOAD: &[u8] = b"staged content";
const RAW_STAGE: &[u8] = b"private-part-\xff";
const PRIVATE_MODE: u32 = 0o600;
const PRIVATE_DIR_MODE: u32 = 0o700;

#[test]
fn the_writer_lease_excludes_inspection_until_the_writer_drops() {
	let fixture = Scratch::new();
	let destination = DestinationRoot::from_directory(fixture.open()).expect("destination root");
	let writer = destination
		.create_job_directory(name(JOB))
		.expect("writer owns exclusive lease");
	let reader = destination
		.open_recovery_job(name(JOB))
		.expect("independent job handle");
	assert!(matches!(reader.try_read_lease(), Err(StageError::JobBusy)));
	drop(writer);
	let _first = reader
		.try_read_lease()
		.expect("acquire a shared reader lease");
	let _second = reader
		.try_read_lease()
		.expect("another reader can share the lease");
}

#[test]
fn fixed_records_reopen_with_read_only_rights_and_distinct_identifiers() {
	let (fixture, root) = fixture();
	let path = fixture.path(JOB);
	let journal = path.join(JOURNAL);
	let receipts = path.join(RECEIPTS);
	private_directory(&journal);
	private_directory(&receipts);
	let paths = [
		path.join(OWNER),
		path.join(PLAN),
		journal.join(FIRST_SEGMENT),
		receipts.join(RECEIPT),
	];
	let records = [b"owner".as_slice(), b"plan", b"segment", b"receipt"];
	for (path, bytes) in paths.iter().zip(records) {
		private_file(path, bytes);
	}

	let job = root.open_recovery_job(name(JOB)).expect("reopen job");
	assert_eq!(job.destination_identity(), root.identity());
	assert_eq!(job.identity().inode(), fs::metadata(path).unwrap().ino());
	let files = [
		job.open_owner(),
		job.open_plan(),
		job.open_first_segment(),
		job.open_receipt(),
	];
	for ((file, path), bytes) in files.into_iter().zip(paths).zip(records) {
		let mut file = file.expect("reopen record");
		assert_read_only(&file);
		let metadata = fs::metadata(path).expect("observe fixture identity");
		assert_eq!(file.identity().device(), metadata.dev());
		assert_eq!(file.identity().inode(), metadata.ino());
		assert!(!file.is_empty());
		let mut output = [0; 8];
		let output = &mut output[..bytes.len()];
		file.read_exact_at(0, output)
			.expect("read without moving cursor");
		assert_eq!(output, bytes);
		file.read_exact(output).expect("read record from cursor");
		assert_eq!(output, bytes);
		file.recheck_observation()
			.expect("allow access-time change");
		file.check_logical_eof()
			.expect("record ends at its observed extent");
		assert_ne!(
			file.extended_attributes()
				.expect("inspect visible attributes"),
			crate::linux::ExtendedAttributes::Present
		);
		assert!(matches!(
			file.read_exact_at(file.len(), &mut [0]),
			Err(ReadError::RangeOutsideFile)
		));
	}
	fixture.assert_debug_redacts(&job, &[JOB]);
}

#[test]
fn reading_the_owned_stage_does_not_advance_its_captured_access_time() {
	let (fixture, root) = fixture();
	let directory = fixture.path(JOB).join(STAGE);
	private_directory(&directory);
	let path = directory.join(std::ffi::OsStr::from_bytes(RAW_STAGE));
	private_file(&path, PAYLOAD);
	let old_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000);
	File::open(&path)
		.unwrap()
		.set_times(FileTimes::new().set_accessed(old_time))
		.expect("set old atime");
	let job = root.open_recovery_job(name(JOB)).expect("reopen job");
	let inventory = job
		.inventory(UnixComponent::new(RAW_STAGE).unwrap(), name(TARGET))
		.expect("inventory stage");
	let stage = inventory.stage().expect("held private stage");
	let mut observed = [0; PAYLOAD.len()];
	stage
		.read_exact_at(0, &mut observed)
		.expect("measure private stage");
	assert_eq!(observed, PAYLOAD);
	assert_eq!(fs::metadata(&path).unwrap().accessed().unwrap(), old_time);
}

#[test]
fn inventory_pins_exact_regular_names_across_an_exclusive_rename() {
	let (fixture, root) = fixture();
	let directory = fixture.path(JOB).join(STAGE);
	private_directory(&directory);
	let stage_path = directory.join(std::ffi::OsStr::from_bytes(RAW_STAGE));
	private_file(&stage_path, PAYLOAD);
	fs::set_permissions(&stage_path, Permissions::from_mode(0o644)).unwrap();
	let target_path = fixture.path(TARGET);
	let job = root.open_recovery_job(name(JOB)).expect("reopen job");
	let stage_name = UnixComponent::new(RAW_STAGE).expect("lossless stage component");
	let inventory = job
		.inventory(stage_name, name(TARGET))
		.expect("inventory stage");
	assert_eq!(
		inventory.stage_directory_identity().unwrap().inode(),
		fs::metadata(&directory).unwrap().ino()
	);
	assert!(inventory.target().is_none());
	let stage = inventory.stage().expect("held private stage");
	let identity = stage.identity();
	assert_eq!(stage.observation().mode(), 0o644);
	assert_read_only(stage);

	fs::rename(stage_path, &target_path).expect("simulate completed rename");
	assert!(matches!(
		inventory.recheck(),
		Err(StageError::IdentityChanged)
	));
	let inventory = job
		.inventory(stage_name, name(TARGET))
		.expect("inventory target");
	assert!(inventory.stage().is_none());
	let target = inventory.target().expect("held target");
	assert_read_only(target);
	assert_eq!(target.identity(), identity);
	let mut data = [0; PAYLOAD.len()];
	target
		.read_exact_at(0, &mut data)
		.expect("read public payload");
	assert_eq!(data, PAYLOAD);
	inventory.recheck().expect("recheck current observations");
	assert_eq!(fs::read(target_path).unwrap(), PAYLOAD);
	fixture.assert_debug_redacts(&inventory, &[TARGET]);
}

#[test]
fn snapshots_distinguish_absence_from_a_late_name_or_directory() {
	let (fixture, root) = fixture();
	let job = root.open_recovery_job(name(JOB)).expect("reopen job");
	let absent_directory = job.inventory(name("part"), name(TARGET)).unwrap();
	assert!(absent_directory.stage_directory_identity().is_none());
	assert!(absent_directory.stage().is_none());
	assert!(absent_directory.target().is_none());

	private_directory(&fixture.path(JOB).join(STAGE));
	assert!(matches!(
		absent_directory.recheck(),
		Err(StageError::IdentityChanged)
	));
	let absent_target = job.inventory(name("part"), name(TARGET)).unwrap();
	fs::write(fixture.path(TARGET), b"late incumbent").unwrap();
	assert!(matches!(
		absent_target.recheck(),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(fs::read(fixture.path(TARGET)).unwrap(), b"late incumbent");
}

#[test]
fn renamed_stage_directory_and_detached_job_fail_rechecks() {
	let (fixture, root) = fixture();
	let job_path = fixture.path(JOB);
	let stage = job_path.join(STAGE);
	private_directory(&stage);
	private_file(&job_path.join(OWNER), b"original job owner");
	let job = root.open_recovery_job(name(JOB)).expect("reopen job");
	let inventory = job.inventory(name("part"), name(TARGET)).unwrap();

	fs::rename(&stage, job_path.join(PARKED)).unwrap();
	private_directory(&stage);
	assert!(matches!(
		inventory.recheck(),
		Err(StageError::IdentityChanged)
	));

	fs::rename(&job_path, fixture.path(PARKED)).unwrap();
	private_directory(&job_path);
	private_file(&job_path.join(OWNER), b"replacement job owner");
	assert!(matches!(job.open_owner(), Err(StageError::IdentityChanged)));
	assert_eq!(
		fs::read(fixture.path(PARKED).join(OWNER)).unwrap(),
		b"original job owner"
	);
}

#[test]
fn changed_record_and_target_observations_fail_closed() {
	let (fixture, root) = fixture();
	let owner = fixture.path(JOB).join(OWNER);
	let target = fixture.path(TARGET);
	private_file(&owner, b"owner");
	fs::write(&target, b"initial target").unwrap();
	let job = root.open_recovery_job(name(JOB)).expect("reopen job");
	let file = job.open_owner().expect("read-only owner");
	let inventory = job.inventory(name("part"), name(TARGET)).unwrap();

	fs::write(owner, b"changed owner").unwrap();
	fs::write(target, b"changed target contents").unwrap();
	assert!(matches!(
		file.recheck_observation(),
		Err(ReadError::SourceChanged)
	));
	assert!(matches!(
		inventory.recheck(),
		Err(StageError::ReadBack(ReadError::SourceChanged))
	));
}

#[test]
fn unsafe_directories_and_record_types_are_rejected() {
	let (fixture, root) = fixture();
	let job_path = fixture.path(JOB);
	let job = root.open_recovery_job(name(JOB)).unwrap();
	let journal = job_path.join(JOURNAL);
	let plan = job_path.join(PLAN);
	let outside = fixture.path("outside");
	private_directory(&outside);
	private_file(&outside.join(FIRST_SEGMENT), b"outside segment");
	private_file(&outside.join(PLAN), b"outside plan");
	symlink(&outside, &journal).unwrap();
	symlink(outside.join(PLAN), &plan).unwrap();
	assert!(matches!(
		job.open_first_segment(),
		Err(StageError::UnsafeDirectory)
	));
	assert!(matches!(job.open_plan(), Err(StageError::UnsafeFile)));
	assert_eq!(fs::read(outside.join(PLAN)).unwrap(), b"outside plan");

	fs::remove_file(&plan).unwrap();
	fs::hard_link(outside.join(PLAN), &plan).unwrap();
	assert!(matches!(job.open_plan(), Err(StageError::UnsafeFile)));
	let owner = job_path.join(OWNER);
	File::create(&owner).unwrap();
	fs::set_permissions(&owner, Permissions::from_mode(0o640)).unwrap();
	assert!(matches!(job.open_owner(), Err(StageError::UnsafeFile)));

	fs::set_permissions(&job_path, Permissions::from_mode(0o750)).unwrap();
	assert!(matches!(
		root.open_recovery_job(name(JOB)),
		Err(StageError::UnsafeDirectory)
	));
}

#[test]
fn symlink_and_fifo_objects_cannot_be_opened_for_inventory_reads() {
	let (fixture, root) = fixture();
	let stage_dir = fixture.path(JOB).join(STAGE);
	private_directory(&stage_dir);
	let stage = stage_dir.join("part");
	let target = fixture.path(TARGET);
	let job = root.open_recovery_job(name(JOB)).unwrap();
	for path in [&stage, &target] {
		symlink("absent", path).unwrap();
		assert!(matches!(
			job.inventory(name("part"), name(TARGET)),
			Err(StageError::UnsafeFile)
		));
		fs::remove_file(path).unwrap();

		linux_fs::mkfifoat(linux_fs::CWD, path, Mode::RUSR).unwrap();
		assert!(matches!(
			job.inventory(name("part"), name(TARGET)),
			Err(StageError::UnsafeFile)
		));
		fs::remove_file(path).unwrap();
	}
}

#[test]
fn missing_records_surface_not_found_and_unsafe_destination_is_rejected() {
	let (fixture, root) = fixture();
	let job = root.open_recovery_job(name(JOB)).unwrap();
	for result in [
		job.open_owner(),
		job.open_plan(),
		job.open_first_segment(),
		job.open_receipt(),
	] {
		assert!(
			matches!(result, Err(StageError::System(error)) if error.kind() == std::io::ErrorKind::NotFound)
		);
	}
	let parent = fixture.path("");
	fs::set_permissions(parent, Permissions::from_mode(0o720)).unwrap();
	assert!(matches!(job.open_owner(), Err(StageError::UnsafeDirectory)));
	assert!(matches!(
		root.open_recovery_job(name(JOB)),
		Err(StageError::UnsafeDirectory)
	));
}

fn fixture() -> (Scratch, DestinationRoot) {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("managed fixture root");
	root.create_job_directory(name(JOB))
		.expect("create private job");
	(fixture, root)
}

fn name(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).expect("validated fixture component")
}

fn private_directory(path: &Path) {
	DirBuilder::new()
		.mode(PRIVATE_DIR_MODE)
		.create(path)
		.expect("private fixture directory");
}

fn private_file(path: &Path, bytes: &[u8]) {
	let mut file = OpenOptions::new()
		.create_new(true)
		.write(true)
		.mode(PRIVATE_MODE)
		.open(path)
		.expect("private fixture file");
	file.write_all(bytes).expect("write fixture bytes");
}

fn assert_read_only(file: &RecoveryFile) {
	let flags = linux_fs::fcntl_getfl(&file.file).expect("inspect descriptor flags");
	assert_eq!(flags & OFlags::ACCMODE, OFlags::RDONLY);
}
