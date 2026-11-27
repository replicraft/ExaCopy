use std::fs::{self, File, FileTimes};
use std::os::unix::fs::{MetadataExt as _, symlink};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use exacopy_endpoint::UnixComponent;
use exacopy_model::{
	CopyBinding, CopyEffect, CopyEvent, CopySession, EntryId, JobId, PublishNoClobber, RunEpoch,
	StageId,
};

use rustix::fs::{XattrFlags, fsetxattr};
use rustix::io::Errno;

use super::{PublishError, StageError};
use crate::linux::job::STAGE;
use crate::linux::{
	DestinationRoot, DirectoryBarriersError, RecoveryInventory, RecoveryWriteLease,
};
use crate::scratch::Scratch;

#[path = "../../../../../tests/unit/linux/recovery/retained.rs"]
mod retained_coverage;

const JOB: &str = "retained-recovery-job";
const PART: &str = "verified-stage";
const TARGET: &str = "public-target";
const PAYLOAD: &[u8] = b"retained stage payload";

#[test]
fn matching_authorization_publishes_the_original_held_inode() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let inode = inventory.stage().unwrap().identity();
	let retained = lease
		.prepare_retained_stage(&inventory, binding(2))
		.unwrap();

	retained
		.publish_no_clobber(authorization(binding(2)))
		.unwrap();

	let after = lease
		.job()
		.inventory(component(PART), component(TARGET))
		.unwrap();
	assert!(after.stage().is_none());
	assert_eq!(after.target().unwrap().identity(), inode);
	assert_eq!(after.target().unwrap().observation().link_count(), 1);
	assert_eq!(fs::read(fixture.target()).unwrap(), PAYLOAD);
}

#[test]
fn retained_capability_rejects_mismatched_binding_and_other_inventory() {
	let fixture = Fixture::new();
	let inspected = fixture.root.open_recovery_job(component(JOB)).unwrap();
	let separate = inspected
		.inventory(component(PART), component(TARGET))
		.unwrap();
	let lease = fixture
		.root
		.try_recovery_write_lease(component(JOB), inspected.identity())
		.unwrap();

	assert!(matches!(
		lease.prepare_retained_stage(&separate, binding(2)),
		Err(StageError::IdentityChanged)
	));
	let inventory = lease
		.job()
		.inventory(component(PART), component(TARGET))
		.unwrap();
	let retained = lease
		.prepare_retained_stage(&inventory, binding(2))
		.unwrap();
	assert!(matches!(
		retained.publish_no_clobber(authorization(binding(1))),
		Err(PublishError::BindingMismatch)
	));

	assert!(!fixture.target().exists());
	assert_eq!(fs::read(fixture.stage()).unwrap(), PAYLOAD);
}

#[test]
fn target_appearing_after_preparation_preserves_both_names() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let retained = lease
		.prepare_retained_stage(&inventory, binding(2))
		.unwrap();

	fs::write(fixture.target(), b"incumbent").unwrap();
	assert!(matches!(
		retained.publish_no_clobber(authorization(binding(2))),
		Err(PublishError::StageChanged(StageError::IdentityChanged))
	));

	assert_eq!(fs::read(fixture.target()).unwrap(), b"incumbent");
	assert_eq!(fs::read(fixture.stage()).unwrap(), PAYLOAD);
	let current = lease
		.job()
		.inventory(component(PART), component(TARGET))
		.unwrap();
	assert!(matches!(
		lease.prepare_retained_stage(&current, binding(3)),
		Err(StageError::IdentityChanged)
	));
}

#[test]
fn changed_or_unsafe_stage_is_preserved() {
	let scenarios: [fn(&Path, &Path); 3] = [
		|stage, _| fs::write(stage, b"changed length").unwrap(),
		|stage, alias| fs::hard_link(stage, alias).unwrap(),
		|stage, alias| {
			fs::rename(stage, alias).unwrap();
			symlink(alias, stage).unwrap();
		},
	];
	for change in scenarios {
		let fixture = Fixture::new();
		let lease = fixture.lease();
		let inventory = inventory(&lease);
		let retained = lease
			.prepare_retained_stage(&inventory, binding(2))
			.unwrap();
		let alias = fixture.scratch.path("preserved-inode");
		change(&fixture.stage(), &alias);

		assert!(matches!(
			retained.publish_no_clobber(authorization(binding(2))),
			Err(PublishError::StageChanged(_))
		));
		assert!(!fixture.target().exists());
		assert!(fixture.stage().exists());
	}
}

#[test]
fn a_visible_stage_attribute_blocks_preparation() {
	let fixture = Fixture::new();
	let file = File::open(fixture.stage()).unwrap();
	fsetxattr(&file, c"user.exacopy-test", b"value", XattrFlags::CREATE).unwrap();
	let lease = fixture.lease();
	let inventory = inventory(&lease);

	assert!(matches!(
		lease.prepare_retained_stage(&inventory, binding(2)),
		Err(StageError::UnexpectedExtendedAttributes)
	));
	assert!(!fixture.target().exists());
	assert_eq!(fs::read(fixture.stage()).unwrap(), PAYLOAD);
}

#[test]
fn access_time_changed_by_an_ordinary_read_blocks_publication() {
	let fixture = Fixture::new();
	let stage = fixture.stage();
	File::open(&stage)
		.unwrap()
		.set_times(FileTimes::new().set_accessed(SystemTime::UNIX_EPOCH))
		.unwrap();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let retained = lease
		.prepare_retained_stage(&inventory, binding(2))
		.unwrap();

	assert_eq!(fs::read(&stage).unwrap(), PAYLOAD);
	// Ordinary inventory validation ignores atime. A retained stage carries it as
	// required metadata, and must reject even when the other observations match.
	inventory.recheck().unwrap();
	assert!(matches!(
		retained.publish_no_clobber(authorization(binding(2))),
		Err(PublishError::StageChanged(StageError::IdentityChanged))
	));
	assert!(matches!(
		lease.prepare_retained_stage(&inventory, binding(2)),
		Err(StageError::IdentityChanged)
	));
	assert!(!fixture.target().exists());
}

#[test]
fn changing_published_inode_during_first_barrier_requires_reconciliation() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let retained = lease
		.prepare_retained_stage(&inventory, binding(2))
		.unwrap();
	let stage = fixture.stage();
	let target = fixture.target();
	let root = fixture.scratch.open().metadata().unwrap().ino();
	let stage_directory = fs::metadata(stage.parent().unwrap()).unwrap().ino();
	let mut calls = Vec::new();

	let result = retained.publish_with_barriers(authorization(binding(2)), |directory| {
		assert!(!stage.exists());
		let inode = directory.metadata().unwrap().ino();
		calls.push(inode);
		if inode == stage_directory {
			fs::hard_link(&target, fixture.scratch.path("unexpected-alias")).unwrap();
		}
		Ok(())
	});

	assert!(matches!(
		result,
		Err(PublishError::ObservationFailed(StageError::UnsafeFile))
	));
	assert_eq!(calls, [stage_directory, root]);
	assert_eq!(fs::read(&target).unwrap(), PAYLOAD);
	assert_eq!(
		fs::read(fixture.scratch.path("unexpected-alias")).unwrap(),
		PAYLOAD
	);
	assert!(!stage.exists());
}

#[test]
fn failed_stage_directory_barrier_leaves_the_rename_in_effect() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let retained = lease
		.prepare_retained_stage(&inventory, binding(2))
		.unwrap();
	let original = inventory.stage().unwrap().identity();
	let stage = fixture.stage();
	let target = fixture.target();
	let mut calls = 0;

	let result = retained.publish_with_barriers(authorization(binding(2)), |_| {
		assert!(!stage.exists());
		assert!(target.exists());
		calls += 1;
		match calls {
			1 => Err(Errno::IO),
			_ => Ok(()),
		}
	});

	assert!(matches!(
		result,
		Err(PublishError::BarriersFailed(DirectoryBarriersError::Stage(error)))
			if error.raw_os_error() == Some(Errno::IO.raw_os_error())
	));
	assert_eq!(calls, 2);
	let after = lease
		.job()
		.inventory(component(PART), component(TARGET))
		.unwrap();
	assert!(after.stage().is_none());
	assert_eq!(after.target().unwrap().identity(), original);
	assert_eq!(fs::read(target).unwrap(), PAYLOAD);
}

struct Fixture {
	scratch: Scratch,
	root: DestinationRoot,
}

impl Fixture {
	fn new() -> Self {
		let scratch = Scratch::new();
		let root = DestinationRoot::from_directory(scratch.open()).expect("managed fixture root");
		let job = root.create_job_directory(component(JOB)).unwrap();
		job.create_stage_directory().unwrap();
		drop(job);
		let fixture = Self { scratch, root };
		fs::write(fixture.stage(), PAYLOAD).unwrap();
		fixture
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
	UnixComponent::new(name.as_bytes()).expect("valid fixture component")
}

fn binding(epoch: u64) -> CopyBinding {
	let job = JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
		.expect("fixture job is UUIDv7");
	CopyBinding::new(
		job,
		EntryId::new(1),
		RunEpoch::new(epoch),
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
		panic!("model refused fixture publication");
	};
	authorization
}
