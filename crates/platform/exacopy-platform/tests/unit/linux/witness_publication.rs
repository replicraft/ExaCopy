use std::ffi::OsStr;
use std::fs::{self, File};

use rustix::fs::{Stat, fstat};

use super::{SourceObservation, WitnessPublicationName, mount_id, observe_name, same_after_rename};
use crate::scratch::Scratch;

#[test]
fn named_publication_observation_pins_the_exact_regular_inode() {
	const NAME: &str = "incumbent";
	const BYTES: &[u8] = b"incumbent bytes";
	let scratch = Scratch::new();
	let directory = scratch.open();
	let mount = mount_id(&directory).expect("observe the private fixture mount");
	let name = OsStr::new(NAME);
	let (state, held) = observe_name(&directory, name, mount);
	assert_eq!(state, WitnessPublicationName::Absent);
	assert!(held.is_none(), "an absent name cannot supply a descriptor");

	let path = scratch.path(NAME);
	fs::write(&path, BYTES).expect("create a regular fixture incumbent");
	let incumbent = File::open(&path).expect("open the fixture incumbent independently");
	let expected = SourceObservation::capture(&fstat(&incumbent).unwrap()).unwrap();
	let (state, held) = observe_name(&directory, name, mount);
	assert_eq!(state, WitnessPublicationName::Regular(expected));
	let held = held.expect("the regular observation must retain its descriptor");
	let pinned = SourceObservation::capture(&fstat(&held).unwrap()).unwrap();
	assert_eq!(pinned, expected);

	let (state, held) = observe_name(&directory, name, mount ^ 1);
	assert_eq!(state, WitnessPublicationName::Unobserved);
	assert!(
		held.is_none(),
		"an unexpected mount cannot supply a descriptor"
	);
	assert_eq!(fs::read(&path).unwrap(), BYTES);
}

#[test]
fn nonregular_publication_name_is_unobserved() {
	const NAME: &str = "directory-incumbent";
	let scratch = Scratch::new();
	let path = scratch.path(NAME);
	fs::create_dir(&path).expect("create a nonregular fixture incumbent");
	let directory = scratch.open();
	let mount = mount_id(&directory).expect("observe the private fixture mount");

	let (state, held) = observe_name(&directory, OsStr::new(NAME), mount);
	assert_eq!(state, WitnessPublicationName::Unobserved);
	assert!(
		held.is_none(),
		"a nonregular name cannot supply a descriptor"
	);
	assert!(path.is_dir(), "the incumbent directory must be preserved");
}

#[test]
fn rename_comparison_requires_the_original_identity_and_metadata() {
	let scratch = Scratch::new();
	let file = File::create(scratch.path("stamp")).expect("create a private regular file");
	let original = fstat(&file).unwrap();
	let before = SourceObservation::capture(&original).unwrap();
	assert!(same_after_rename(before, before));

	let mut rename_times = original;
	rename_times.st_atime = original.st_atime.checked_add(1).unwrap();
	rename_times.st_ctime = original.st_ctime.checked_add(1).unwrap();
	let after = SourceObservation::capture(&rename_times).unwrap();
	assert_ne!(before.accessed_at(), after.accessed_at());
	assert_ne!(before.changed_at(), after.changed_at());
	assert!(same_after_rename(before, after));

	let changes: [(&str, fn(&mut Stat)); 8] = [
		("device", |stat| stat.st_dev ^= 1),
		("inode", |stat| stat.st_ino ^= 1),
		("length", |stat| stat.st_size = 1),
		("mode", |stat| stat.st_mode ^= 0o100),
		("owner", |stat| stat.st_uid ^= 1),
		("group", |stat| stat.st_gid ^= 1),
		("mtime", |stat| {
			stat.st_mtime = stat.st_mtime.checked_add(1).unwrap();
		}),
		("link count", |stat| stat.st_nlink ^= 1),
	];
	for (field, change) in changes {
		let mut changed = rename_times;
		change(&mut changed);
		let changed = SourceObservation::capture(&changed).unwrap();
		assert!(
			!same_after_rename(before, changed),
			"changed {field} was accepted"
		);
	}
}
