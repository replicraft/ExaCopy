use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::PathBuf;

use exacopy_model::{CopyBinding, EntryId, JobId, RunEpoch, StageId};

use super::{FileIdentity, RecoveryInventory, RecoveryWriteLease, StageError, UnixComponent};
use crate::linux::DestinationRoot;
use crate::linux::job::STAGE;
use crate::scratch::Scratch;

const JOB: &str = "fresh-recovery-job";
const OLD: &str = "prior-attempt";
const FRESH: &str = "next-attempt";
const TARGET: &str = "public-target";
const ORIGINAL: &[u8] = b"retained old bytes";
const NEW: &[u8] = b"fresh data";
const INCUMBENT: &[u8] = b"incumbent";

#[test]
fn creates_a_fresh_sibling_once_and_retains_the_old_stage() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let previous = fixture.inventory(&lease, OLD);
	let old_identity = previous.stage().unwrap().identity();
	let fresh = fixture.inventory(&lease, FRESH);
	let mut prepared = lease
		.prepare_fresh_stage(&fresh, fixture.directory)
		.unwrap();
	assert_eq!(prepared.identity(), fixture.directory);
	assert!(matches!(
		lease.reopen_stage_directory(&previous),
		Err(StageError::JobBusy)
	));
	{
		let mut writer = prepared.create_writer(binding(2)).unwrap();
		assert_ne!(writer.identity(), old_identity);
		assert_eq!(fs::metadata(fixture.stage(FRESH)).unwrap().len(), 0);
		writer.write_all_at(0, NEW).unwrap();
		writer.flush().unwrap();
		let closed = writer.close_writes().unwrap();
		let mut bytes = [0; NEW.len()];
		closed.read_exact_at(0, &mut bytes).unwrap();
		assert_eq!(bytes, NEW);
	}
	assert!(matches!(
		prepared.create_writer(binding(2)),
		Err(StageError::IdentityChanged)
	));
	previous.recheck().unwrap();
	assert_eq!(fs::read(fixture.stage(OLD)).unwrap(), ORIGINAL);
	assert_eq!(fs::read(fixture.stage(FRESH)).unwrap(), NEW);
	assert!(!fixture.scratch.path(TARGET).exists());
}

#[test]
fn refuses_foreign_inventory_wrong_directory_or_occupied_selected_name() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let separate = fixture.root.open_recovery_job(name(JOB)).unwrap();
	let foreign = separate.inventory(name(FRESH), name(TARGET)).unwrap();
	let vacant = fixture.inventory(&lease, FRESH);
	let occupied = fixture.inventory(&lease, OLD);
	for (observation, expected) in [
		(&foreign, fixture.directory),
		(&vacant, lease.job().identity()),
		(&occupied, fixture.directory),
	] {
		assert!(matches!(
			lease.prepare_fresh_stage(observation, expected),
			Err(StageError::IdentityChanged)
		));
	}
	let target = fixture.scratch.path(TARGET);
	fs::write(&target, INCUMBENT).unwrap();
	let occupied_target = fixture.inventory(&lease, FRESH);
	assert!(matches!(
		lease.prepare_fresh_stage(&occupied_target, fixture.directory),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(fs::read(target).unwrap(), INCUMBENT);

	assert!(!fixture.stage(FRESH).exists());
	assert_eq!(fs::read(fixture.stage(OLD)).unwrap(), ORIGINAL);
}

#[test]
fn refuses_rebound_directory_and_changed_stage_name_before_creation() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let vacant = fixture.inventory(&lease, FRESH);
	{
		let mut prepared = lease
			.prepare_fresh_stage(&vacant, fixture.directory)
			.unwrap();
		let old = fixture.stage(OLD);
		symlink(&old, fixture.stage(FRESH)).unwrap();
		assert!(prepared.create_writer(binding(2)).is_err());
		assert!(
			fs::symlink_metadata(fixture.stage(FRESH))
				.unwrap()
				.is_symlink()
		);
		assert_eq!(fs::read(&old).unwrap(), ORIGINAL);
		fs::remove_file(fixture.stage(FRESH)).unwrap();
	}
	let vacant = fixture.inventory(&lease, FRESH);
	let mut prepared = lease
		.prepare_fresh_stage(&vacant, fixture.directory)
		.unwrap();
	let job = fixture.scratch.path(JOB);
	let directory = job.join(STAGE);
	let retained = job.join("retained-stage-directory");
	fs::rename(&directory, &retained).unwrap();
	fs::create_dir(&directory).unwrap();
	fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
	assert!(matches!(
		prepared.create_writer(binding(2)),
		Err(StageError::IdentityChanged)
	));
	assert!(!directory.join(FRESH).exists());
	assert!(!retained.join(FRESH).exists());
	assert_eq!(fs::read(retained.join(OLD)).unwrap(), ORIGINAL);
}

#[test]
fn failed_stage_barrier_spends_the_allocation_and_retains_new_and_old_files() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let vacant = fixture.inventory(&lease, FRESH);
	let mut prepared = lease
		.prepare_fresh_stage(&vacant, fixture.directory)
		.unwrap();
	let result = prepared.create_with(binding(2), |_| {
		assert_eq!(fs::metadata(fixture.stage(FRESH)).unwrap().len(), 0);
		Err(StageError::DirectoryBarrierFailed(std::io::Error::other(
			"fixture barrier",
		)))
	});
	assert!(matches!(result, Err(StageError::DirectoryBarrierFailed(_))));
	assert_eq!(fs::read(fixture.stage(FRESH)).unwrap(), b"");
	let parked = fixture.stage("retained-after-failed-barrier");
	fs::rename(fixture.stage(FRESH), &parked).unwrap();
	assert!(matches!(
		prepared.create_writer(binding(2)),
		Err(StageError::IdentityChanged)
	));
	assert!(!fixture.stage(FRESH).exists());
	assert_eq!(fs::read(parked).unwrap(), b"");
	assert_eq!(fs::read(fixture.stage(OLD)).unwrap(), ORIGINAL);
	assert!(!fixture.scratch.path(TARGET).exists());
}

#[test]
fn late_incumbent_and_rebound_file_after_creation_prevent_writer_handoff() {
	for rebind_stage in [false, true] {
		let fixture = Fixture::new();
		let lease = fixture.lease();
		let vacant = fixture.inventory(&lease, FRESH);
		let mut prepared = lease
			.prepare_fresh_stage(&vacant, fixture.directory)
			.unwrap();
		let parked = fixture.stage("parked-new-file");
		let target = fixture.scratch.path(TARGET);
		let result = prepared.create_with(binding(2), |directory| {
			if rebind_stage {
				fs::rename(fixture.stage(FRESH), &parked).unwrap();
				fs::write(fixture.stage(FRESH), INCUMBENT).unwrap();
				fs::set_permissions(fixture.stage(FRESH), fs::Permissions::from_mode(0o600))
					.unwrap();
			} else {
				fs::write(&target, INCUMBENT).unwrap();
			}
			directory.sync_directory()
		});
		assert!(matches!(result, Err(StageError::IdentityChanged)));
		assert_eq!(fs::read(fixture.stage(OLD)).unwrap(), ORIGINAL);
		if rebind_stage {
			assert_eq!(fs::read(fixture.stage(FRESH)).unwrap(), INCUMBENT);
			assert_eq!(fs::read(parked).unwrap(), b"");
			assert!(!target.exists());
		} else {
			assert_eq!(fs::read(&target).unwrap(), INCUMBENT);
			assert_eq!(fs::read(fixture.stage(FRESH)).unwrap(), b"");
		}
	}
}

struct Fixture {
	scratch: Scratch,
	root: DestinationRoot,
	directory: FileIdentity,
}

impl Fixture {
	fn new() -> Self {
		let scratch = Scratch::new();
		let root = DestinationRoot::from_directory(scratch.open()).unwrap();
		let directory = {
			let job = root.create_job_directory(name(JOB)).unwrap();
			let stage = job.create_stage_directory().unwrap();
			let mut old = stage
				.create_file(name(OLD), name(TARGET), binding(1))
				.unwrap();
			old.write_all_at(0, ORIGINAL).unwrap();
			old.flush().unwrap();
			stage.sync_directory().unwrap();
			job.sync_directory().unwrap();
			stage.identity()
		};
		Self {
			scratch,
			root,
			directory,
		}
	}

	fn lease(&self) -> RecoveryWriteLease<'_> {
		let inspected = self.root.open_recovery_job(name(JOB)).unwrap();
		self.root
			.try_recovery_write_lease(name(JOB), inspected.identity())
			.unwrap()
	}

	fn inventory<'lease>(
		&self,
		lease: &'lease RecoveryWriteLease<'lease>,
		stage: &str,
	) -> RecoveryInventory<'lease> {
		lease.job().inventory(name(stage), name(TARGET)).unwrap()
	}

	fn stage(&self, file: &str) -> PathBuf {
		self.scratch.path(JOB).join(STAGE).join(file)
	}
}

fn name(bytes: &str) -> UnixComponent<'_> {
	UnixComponent::new(bytes.as_bytes()).unwrap()
}

fn binding(epoch: u64) -> CopyBinding {
	let job =
		JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]).unwrap();
	CopyBinding::new(
		job,
		EntryId::new(1),
		RunEpoch::new(epoch),
		StageId::from_bytes([u8::try_from(epoch).unwrap(); 16]),
	)
}
