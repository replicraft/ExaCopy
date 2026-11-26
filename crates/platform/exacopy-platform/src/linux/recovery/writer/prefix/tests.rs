use std::ffi::OsStr;
use std::fs::{self, File, FileTimes, Permissions};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::time::SystemTime;

use exacopy_endpoint::{ReadView, UnixComponent};

use super::RetainedPrefixSelection;
use crate::linux::job::STAGE;
use crate::linux::{DestinationRoot, RecoveryInventory, RecoveryWriteLease, StageError};
use crate::scratch::Scratch;

const JOB: &str = "prefix-fixture-job";
const NAME: &[u8] = b"capture-\xff";
const TARGET: &[u8] = b"selected-target";
const PREFIX: &[u8] = b"first private prefix";

#[test]
fn retained_prefix_pins_the_same_lease_and_reads_exact_bytes() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let expected = selection(&inventory);
	let read = lease.read_retained_prefix(&inventory, expected).unwrap();
	assert_eq!(read.selection(), expected);
	assert_eq!(read.length(), PREFIX.len() as u64);
	let mut bytes = [0; PREFIX.len()];
	read.read_exact_at(0, &mut bytes).unwrap();
	assert_eq!(&bytes, PREFIX);
	assert!(read.read_exact_at(1, &mut bytes).is_err());
	read.recheck_observation().unwrap();
	assert!(matches!(
		lease.reopen_stage_directory(&inventory),
		Err(StageError::JobBusy)
	));
	let debug = format!("{read:?}");
	assert!(!debug.contains("capture-") && !debug.contains("selected-target"));
	drop(read);
	assert!(lease.reopen_stage_directory(&inventory).is_ok());
	assert_eq!(fs::read(fixture.stage()).unwrap(), PREFIX);
	assert!(!fixture.target().exists());
}

#[test]
fn rejects_foreign_inventory_and_each_substituted_binding() {
	let fixture = Fixture::new();
	let foreign = fixture
		.root
		.open_recovery_job(component(JOB.as_bytes()))
		.unwrap();
	let foreign = foreign
		.inventory(component(NAME), component(TARGET))
		.unwrap();
	let lease = fixture.lease();
	let inventory = inventory(&lease);
	let expected = selection(&inventory);
	let names = [
		RetainedPrefixSelection {
			stage: component(b"capture-\xfe"),
			..expected
		},
		RetainedPrefixSelection {
			target: component(b"other-integrity-scope"),
			..expected
		},
		RetainedPrefixSelection {
			directory: expected.file,
			..expected
		},
		RetainedPrefixSelection {
			file: expected.directory,
			..expected
		},
	];
	for wrong in names {
		assert!(matches!(
			lease.read_retained_prefix(&inventory, wrong),
			Err(StageError::IdentityChanged)
		));
	}
	assert!(matches!(
		lease.read_retained_prefix(&foreign, expected),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(fs::read(fixture.stage()).unwrap(), PREFIX);
	assert!(!fixture.target().exists());
}

#[test]
fn held_prefix_recheck_detects_same_extent_change_and_name_replacement() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let inventory_before = inventory(&lease);
	let read = lease
		.read_retained_prefix(&inventory_before, selection(&inventory_before))
		.unwrap();
	let path = fixture.stage();
	let changed = vec![b'z'; PREFIX.len()];
	fs::write(&path, &changed).unwrap();
	File::open(&path)
		.unwrap()
		.set_times(FileTimes::new().set_modified(SystemTime::UNIX_EPOCH))
		.unwrap();
	assert!(read.recheck_observation().is_err());
	assert_eq!(fs::read(&path).unwrap(), changed);

	drop(read);
	let captured = inventory(&lease);
	let read = lease
		.read_retained_prefix(&captured, selection(&captured))
		.unwrap();
	let detached = fixture.scratch.path("detached-prefix");
	fs::rename(&path, &detached).unwrap();
	private_file(&path, &changed);
	assert!(read.recheck_observation().is_err());
	assert_eq!(fs::read(&detached).unwrap(), changed);
	assert_eq!(fs::read(&path).unwrap(), changed);
}

#[test]
fn refuses_an_incumbent_before_or_after_lease_and_an_unsafe_stage_mode() {
	let fixture = Fixture::new();
	let lease = fixture.lease();
	let before = inventory(&lease);
	let read = lease
		.read_retained_prefix(&before, selection(&before))
		.unwrap();
	fs::write(fixture.target(), b"incumbent").unwrap();
	assert!(read.recheck_observation().is_err());
	drop(read);

	let after = inventory(&lease);
	assert!(matches!(
		lease.read_retained_prefix(&after, selection(&after)),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(fs::read(fixture.target()).unwrap(), b"incumbent");
	assert_eq!(fs::read(fixture.stage()).unwrap(), PREFIX);

	fs::remove_file(fixture.target()).unwrap();
	fs::set_permissions(fixture.stage(), Permissions::from_mode(0o640)).unwrap();
	let unsafe_mode = inventory(&lease);
	assert!(matches!(
		lease.read_retained_prefix(&unsafe_mode, selection(&unsafe_mode)),
		Err(StageError::UnsafeFile)
	));
	assert_eq!(fs::read(fixture.stage()).unwrap(), PREFIX);
}

struct Fixture {
	scratch: Scratch,
	root: DestinationRoot,
}

impl Fixture {
	fn new() -> Self {
		let scratch = Scratch::new();
		let root = DestinationRoot::from_directory(scratch.open()).unwrap();
		let job = root
			.create_job_directory(component(JOB.as_bytes()))
			.unwrap();
		job.create_stage_directory().unwrap();
		drop(job);
		let fixture = Self { scratch, root };
		private_file(fixture.stage(), PREFIX);
		fixture
	}

	fn lease(&self) -> RecoveryWriteLease<'_> {
		let name = component(JOB.as_bytes());
		let job = self.root.open_recovery_job(name).unwrap();
		self.root
			.try_recovery_write_lease(name, job.identity())
			.unwrap()
	}

	fn stage(&self) -> PathBuf {
		self.scratch
			.path(JOB)
			.join(STAGE)
			.join(OsStr::from_bytes(NAME))
	}

	fn target(&self) -> PathBuf {
		self.scratch.path("").join(OsStr::from_bytes(TARGET))
	}
}

fn private_file(path: impl AsRef<std::path::Path>, bytes: &[u8]) {
	fs::write(&path, bytes).unwrap();
	fs::set_permissions(path, Permissions::from_mode(0o600)).unwrap();
}

fn inventory<'lease>(lease: &'lease RecoveryWriteLease<'lease>) -> RecoveryInventory<'lease> {
	lease
		.job()
		.inventory(component(NAME), component(TARGET))
		.unwrap()
}

fn selection(inventory: &RecoveryInventory<'_>) -> RetainedPrefixSelection<'static> {
	RetainedPrefixSelection {
		stage: component(NAME),
		target: component(TARGET),
		directory: inventory.stage_directory_identity().unwrap().into(),
		file: inventory.stage().unwrap().identity().into(),
	}
}

fn component(bytes: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(bytes).unwrap()
}
