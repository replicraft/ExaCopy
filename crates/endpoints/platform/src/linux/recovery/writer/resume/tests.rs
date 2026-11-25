use std::fs::{self, File, FileTimes, Permissions};
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

use exacopy_endpoint::UnixComponent;
use exacopy_model::{
	CopyBinding, CopyEffect, CopyEvent, CopySession, EntryId, JobId, PublishNoClobber, RunEpoch,
	StageId,
};
use rustix::fs::{XattrFlags, fsetxattr};

use super::{RecoveryInventory, RecoveryWriteLease, StageError};
use crate::linux::job::STAGE;
use crate::linux::{DestinationRoot, PublishError};
use crate::scratch::Scratch;

const JOB: &str = "resumable-job";
const PART: &str = "retained-part";
const TARGET: &str = "public-target";
const ORIGINAL: &[u8] = b"prefix data tail";
const COMPLETED: &[u8] = b"prefix new! tail";
const INCUMBENT: &[u8] = b"incumbent";

#[test]
fn reopens_without_truncation_and_preserves_a_late_incumbent() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let retained = inventory.stage().unwrap();
	let mut observed = [0; ORIGINAL.len()];
	retained.read_exact_at(0, &mut observed).unwrap();
	assert_eq!(observed, ORIGINAL);
	let mut directory = lease.reopen_stage_directory(&inventory).unwrap();
	assert_eq!(
		Some(directory.identity()),
		inventory.stage_directory_identity()
	);
	let mut writer = directory.open_writer(binding()).unwrap();
	assert_eq!(writer.identity(), retained.identity());
	assert_eq!(fs::metadata(fixture.stage()).unwrap().len(), retained.len());
	writer.write_all_at(7, b"new!").unwrap();
	writer.flush().unwrap();
	let closed = writer.close_writes().unwrap();
	assert_eq!(closed.identity(), retained.identity());
	closed.sync_stage_directory().unwrap();
	closed.read_exact_at(0, &mut observed).unwrap();
	assert_eq!(observed, COMPLETED);

	fs::write(fixture.target(), INCUMBENT).unwrap();
	assert!(matches!(
		closed.publish_no_clobber(authorization(binding())),
		Err(PublishError::Conflict)
	));
	assert_eq!(fs::read(fixture.target()).unwrap(), INCUMBENT);
	assert_eq!(fs::read(fixture.stage()).unwrap(), COMPLETED);
}

#[test]
fn writer_rechecks_both_names_after_directory_preflight() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let mut directory = lease.reopen_stage_directory(&inventory).unwrap();
	fs::write(fixture.target(), INCUMBENT).unwrap();
	assert!(matches!(
		directory.open_writer(binding()),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(fs::read(fixture.target()).unwrap(), INCUMBENT);
	fs::remove_file(fixture.target()).unwrap();
	let saved = fixture.stage().with_file_name("saved-original");
	fs::rename(fixture.stage(), &saved).unwrap();
	fs::write(fixture.stage(), INCUMBENT).unwrap();
	assert!(matches!(
		directory.open_writer(binding()),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(fs::read(fixture.stage()).unwrap(), INCUMBENT);
	assert_eq!(fs::read(saved).unwrap(), ORIGINAL);
}

#[test]
fn stale_generation_or_rebound_stage_directory_leaves_existing_bytes() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	{
		let inventory = inventory(&lease);
		let mut directory = lease.reopen_stage_directory(&inventory).unwrap();
		fs::write(fixture.stage(), COMPLETED).unwrap();
		// Distinguish the observation even when both writes fall in one
		// filesystem clock tick.
		File::open(fixture.stage())
			.unwrap()
			.set_times(FileTimes::new().set_modified(UNIX_EPOCH))
			.unwrap();
		assert!(matches!(
			directory.open_writer(binding()),
			Err(StageError::ReadBack(_))
		));
	}
	let inventory = inventory(&lease);
	let mut directory = lease.reopen_stage_directory(&inventory).unwrap();
	let renamed = fixture.scratch.path(JOB).join("old-stage");
	let current = fixture.scratch.path(JOB).join(STAGE);
	fs::rename(&current, &renamed).unwrap();
	fs::create_dir(&current).unwrap();
	fs::set_permissions(&current, Permissions::from_mode(0o700)).unwrap();
	assert!(matches!(
		directory.open_writer(binding()),
		Err(StageError::IdentityChanged)
	));
	assert!(!fixture.stage().exists());
	assert_eq!(fs::read(renamed.join(PART)).unwrap(), COMPLETED);
}

#[test]
fn rejects_unsafe_mode_links_and_visible_attributes() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let stage = fixture.stage();
	fs::set_permissions(&stage, Permissions::from_mode(0o640)).unwrap();
	{
		let inventory = inventory(&lease);
		let mut directory = lease.reopen_stage_directory(&inventory).unwrap();
		assert!(matches!(
			directory.open_writer(binding()),
			Err(StageError::UnsafeFile)
		));
	}
	fs::set_permissions(&stage, Permissions::from_mode(0o600)).unwrap();
	let alias = fixture.scratch.path("stage-alias");
	{
		let inventory = inventory(&lease);
		let mut directory = lease.reopen_stage_directory(&inventory).unwrap();
		fs::hard_link(&stage, &alias).unwrap();
		assert!(matches!(
			directory.open_writer(binding()),
			Err(StageError::UnsafeFile)
		));
	}
	assert_eq!(fs::read(&alias).unwrap(), ORIGINAL);
	fs::remove_file(alias).unwrap();
	fsetxattr(
		File::open(&stage).unwrap(),
		c"user.synthetic",
		b"value",
		XattrFlags::CREATE,
	)
	.unwrap();
	let inventory = inventory(&lease);
	let mut directory = lease.reopen_stage_directory(&inventory).unwrap();
	assert!(matches!(
		directory.open_writer(binding()),
		Err(StageError::UnexpectedExtendedAttributes)
	));
	assert_eq!(fs::read(stage).unwrap(), ORIGINAL);
	assert!(!fixture.target().exists());
}

#[test]
fn rejects_an_inventory_from_a_different_handle_and_overlapping_stage_capabilities() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let other = fixture.root.open_recovery_job(component(JOB)).unwrap();
	let separate = other.inventory(component(PART), component(TARGET)).unwrap();
	assert!(matches!(
		lease.reopen_stage_directory(&separate),
		Err(StageError::IdentityChanged)
	));
	let inventory = inventory(&lease);
	{
		let _directory = lease.reopen_stage_directory(&inventory).unwrap();
		assert!(matches!(
			lease.reopen_stage_directory(&inventory),
			Err(StageError::JobBusy)
		));
		assert!(matches!(
			lease.prepare_retained_stage(&inventory, binding()),
			Err(StageError::JobBusy)
		));
	}
	let _retained = lease.prepare_retained_stage(&inventory, binding()).unwrap();
	assert!(matches!(
		lease.reopen_stage_directory(&inventory),
		Err(StageError::JobBusy)
	));
}

struct Fixture {
	scratch: Scratch,
	root: DestinationRoot,
}

impl Fixture {
	fn new() -> Self {
		let scratch = Scratch::new();
		let root = DestinationRoot::from_directory(scratch.open()).unwrap();
		{
			let job = root.create_job_directory(component(JOB)).unwrap();
			let directory = job.create_stage_directory().unwrap();
			let mut writer = directory
				.create_file(component(PART), component(TARGET), binding())
				.unwrap();
			writer.write_all_at(0, ORIGINAL).unwrap();
			writer.flush().unwrap();
		}
		Self { scratch, root }
	}

	fn lease(&self) -> RecoveryWriteLease<'_> {
		let job = self.root.open_recovery_job(component(JOB)).unwrap();
		self.root
			.try_recovery_write_lease(component(JOB), job.identity())
			.unwrap()
	}

	fn stage(&self) -> PathBuf {
		self.scratch.path(JOB).join(STAGE).join(PART)
	}

	fn target(&self) -> PathBuf {
		self.scratch.path(TARGET)
	}
}

fn inventory<'lease>(lease: &'lease RecoveryWriteLease<'lease>) -> RecoveryInventory<'lease> {
	lease
		.job()
		.inventory(component(PART), component(TARGET))
		.unwrap()
}

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).unwrap()
}

fn binding() -> CopyBinding {
	let job =
		JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]).unwrap();
	CopyBinding::new(
		job,
		EntryId::new(1),
		RunEpoch::new(2),
		StageId::from_bytes([1; 16]),
	)
}

fn authorization(binding: CopyBinding) -> PublishNoClobber {
	let mut session = CopySession::new(binding);
	for event in [
		CopyEvent::StagePrepared,
		CopyEvent::WritersJoined,
		CopyEvent::DataFlushed,
		CopyEvent::ReadbackVerified,
		CopyEvent::MetadataReady,
		CopyEvent::StageSealed,
	] {
		let _ = session.apply(binding, event).unwrap();
	}
	let Some(CopyEffect::PublishNoClobber(authorization)) = session
		.apply(binding, CopyEvent::PublishIntentRecorded)
		.unwrap()
	else {
		panic!("fixture model did not authorize publication");
	};
	authorization
}
