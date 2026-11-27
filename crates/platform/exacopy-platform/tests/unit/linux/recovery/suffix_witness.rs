use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use exacopy_endpoint::UnixComponent;

use super::{check_aliases, mount_id, observe_two_names, same_stage_after_link};
use crate::linux::job::STAGE;
use crate::linux::{
	DestinationRoot, ReadError, RetainedPrefixSelection, SourceObservation, StageError,
};
use crate::scratch::Scratch;

const PREFIX: &[u8] = b"retained prefix";

#[test]
fn one_link_stage_refuses_two_name_observation_and_preserves_a_distinct_incumbent() {
	const JOB: &str = "suffix-witness-fixture";
	const STAGE_NAME: &str = "private-stage";
	const TARGET: &str = "selected-target";
	const WITNESS: [u8; 40] = *b"witness.0123456789abcdef0123456789abcdef";
	const INCUMBENT: &[u8] = b"unrelated witness slot occupant";
	const END: u64 = PREFIX.len() as u64;

	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).expect("hold the fixture root");
	let job = root
		.create_job_directory(component(JOB))
		.expect("create the owner-private fixture job");
	job.create_stage_directory()
		.expect("create the fixture stage directory");
	drop(job);
	let stage = scratch.path(JOB).join(STAGE).join(STAGE_NAME);
	let witness = scratch.path(JOB).join(OsStr::from_bytes(&WITNESS));
	private_file(&stage, PREFIX);
	private_file(&witness, INCUMBENT);
	let job = root
		.open_recovery_job(component(JOB))
		.expect("hold the private fixture job");
	let lease = root
		.try_recovery_write_lease(component(JOB), job.identity())
		.expect("hold the exact fixture lease");
	let inventory = lease
		.job()
		.inventory(component(STAGE_NAME), component(TARGET))
		.expect("select the original retained stage and absent target");
	let selection = RetainedPrefixSelection {
		stage: component(STAGE_NAME),
		target: component(TARGET),
		directory: inventory.stage_directory_identity().unwrap().into(),
		file: inventory.stage().unwrap().identity().into(),
	};
	let reader = lease
		.read_retained_prefix(&inventory, selection)
		.expect("pin the selected fixture stage");
	let readback = reader
		.sync_adopted(END, |_, _| Ok::<_, ()>(()))
		.expect("sync the original private prefix")
		.zero_tail_readback(END, |actual, range| {
			assert_eq!(actual, selection);
			assert_eq!(range, END..END);
			Ok::<_, ()>(())
		})
		.expect("open the exact read-only zero-tail stage");

	assert!(matches!(
		observe_two_names(&readback, &WITNESS),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(fs::read(&stage).unwrap(), PREFIX);
	assert_eq!(fs::metadata(&stage).unwrap().nlink(), 1);
	assert_eq!(fs::read(&witness).unwrap(), INCUMBENT);
	assert_eq!(fs::metadata(witness).unwrap().nlink(), 1);
	assert_absent(scratch.path(TARGET));
}

#[test]
fn link_transition_allows_ctime_and_atime_to_change_but_preserves_stage_facts() {
	let scratch = Scratch::new();
	let path = scratch.path("link-observation");
	private_file(&path, PREFIX);
	let file = File::open(path).expect("open synthetic ordinary file");
	let original = rustix::fs::fstat(&file).expect("observe an ordinary single-link inode");
	let before = observation(&original);
	assert_eq!(before.link_count(), 1);

	let mut linked = original;
	linked.st_nlink = 2;
	linked.st_atime ^= 1;
	linked.st_ctime ^= 1;
	let after = observation(&linked);
	assert_ne!(before.accessed_at(), after.accessed_at());
	assert_ne!(before.changed_at(), after.changed_at());
	assert!(same_stage_after_link(before, after));
	assert!(
		!same_stage_after_link(after, after),
		"old count must be one"
	);

	type StatChange = (&'static str, fn(&mut rustix::fs::Stat));
	let changes: [StatChange; 8] = [
		("device", |stat| stat.st_dev ^= 1),
		("inode", |stat| stat.st_ino ^= 1),
		("length", |stat| stat.st_size ^= 1),
		("mode", |stat| stat.st_mode ^= 0o100),
		("owner", |stat| stat.st_uid ^= 1),
		("group", |stat| stat.st_gid ^= 1),
		("mtime", |stat| stat.st_mtime ^= 1),
		("third link", |stat| stat.st_nlink = 3),
	];
	for (field, change) in changes {
		let mut changed = linked;
		change(&mut changed);
		assert!(
			!same_stage_after_link(before, observation(&changed)),
			"link transition accepted drift in {field}"
		);
	}
	assert!(
		!same_stage_after_link(before, before),
		"new count must be two"
	);
}

#[test]
fn alias_recheck_requires_both_descriptors_to_match_the_mount_and_inode() {
	let scratch = Scratch::new();
	let first_path = scratch.path("expected");
	let other_path = scratch.path("different");
	private_file(&first_path, PREFIX);
	private_file(&other_path, PREFIX);
	let opened = || File::open(&first_path).expect("open the same synthetic inode");
	let held = [opened(), opened()];
	let mount = mount_id(&held[0]).expect("observe the existing fixture mount");
	let stat = rustix::fs::fstat(&held[0]).expect("observe the expected fixture inode");
	let stamp = observation(&stat);
	check_aliases(&held, stamp, mount).expect("both held descriptors match the expected stamp");
	assert!(matches!(
		check_aliases(&held, stamp, mount ^ 1),
		Err(StageError::IdentityChanged)
	));

	let different = [
		opened(),
		File::open(other_path).expect("open the distinct, equal-content fixture inode"),
	];
	assert!(matches!(
		check_aliases(&different, stamp, mount),
		Err(StageError::ReadBack(ReadError::IdentityChanged))
	));
	let directory_alias = [opened(), scratch.open()];
	assert!(matches!(
		check_aliases(&directory_alias, stamp, mount),
		Err(StageError::ReadBack(ReadError::NotRegularFile))
	));

	let mut stale = stat;
	stale.st_mtime ^= 1;
	assert!(matches!(
		check_aliases(&held, observation(&stale), mount),
		Err(StageError::ReadBack(ReadError::SourceChanged))
	));
}

fn observation(stat: &rustix::fs::Stat) -> SourceObservation {
	SourceObservation::capture(stat).expect("the synthetic regular-file observation is valid")
}

fn assert_absent(path: PathBuf) {
	let error = fs::symlink_metadata(path).expect_err("name should remain absent");
	assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

fn private_file(path: &Path, bytes: &[u8]) {
	let mut file = OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(path)
		.expect("exclusively create an owner-private fixture file");
	file.set_permissions(Permissions::from_mode(0o600))
		.expect("set the exact fixture mode despite the process umask");
	file.write_all(bytes)
		.expect("write synthetic fixture bytes");
}

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).expect("fixture name is one safe component")
}
