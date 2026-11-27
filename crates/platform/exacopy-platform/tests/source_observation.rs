//! Native Linux source observations and extended-attribute inspection.

#![cfg(target_os = "linux")]

mod common;

use std::fs::{self, File, FileTimes, Permissions};
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::time::{Duration, UNIX_EPOCH};

use exacopy_endpoint::UnixComponent;
use exacopy_platform::linux::{ExtendedAttributes, ReadError, ReadRoot};
use rustix::fs::{self as unix, XattrFlags};

use common::Scratch;

const SOURCE: &str = "source-observation-fixture";

#[test]
fn captures_descriptor_identity_and_basic_metadata_at_open() {
	let scratch = Scratch::new();
	let path = scratch.path(SOURCE);
	fs::write(&path, b"contents").expect("write source fixture");
	let file = File::open(&path).expect("open metadata fixture");
	file.set_permissions(Permissions::from_mode(0o640))
		.expect("set ordinary permissions");
	file.set_times(
		FileTimes::new()
			.set_accessed(UNIX_EPOCH + Duration::new(100, 15))
			.set_modified(UNIX_EPOCH + Duration::new(200, 25)),
	)
	.expect("set known source times");
	let raw = file.metadata().expect("inspect kernel fixture metadata");
	let root = ReadRoot::from_directory(scratch.open()).expect("admit source root");
	let source = root
		.open_regular(UnixComponent::new(SOURCE.as_bytes()).expect("valid name"))
		.expect("open source file");
	let observation = source.observation();
	scratch.assert_debug_redacts(&observation, &[SOURCE]);
	assert_eq!(observation.identity(), source.identity());
	assert_eq!(observation.identity().device(), raw.dev());
	assert_eq!(observation.identity().inode(), raw.ino());
	assert_eq!(
		observation.native_mode(),
		raw.mode(),
		"native mode must include the regular-file type bits"
	);
	assert_eq!(observation.len(), 8);
	assert!(!observation.is_empty());
	assert_eq!(observation.link_count(), 1);
	assert_eq!(observation.mode(), 0o640);
	assert_eq!(observation.owner(), raw.uid());
	assert_eq!(observation.group(), raw.gid());
	for (actual, seconds, nanos) in [
		(observation.accessed_at(), raw.atime(), raw.atime_nsec()),
		(observation.modified_at(), raw.mtime(), raw.mtime_nsec()),
		(observation.changed_at(), raw.ctime(), raw.ctime_nsec()),
	] {
		assert_eq!(actual.seconds(), seconds);
		assert_eq!(i64::from(actual.nanoseconds()), nanos);
	}
	let mut contents = [0; 8];
	source.read_exact_at(0, &mut contents).expect("read source");
	assert_eq!(&contents, b"contents");
	source
		.recheck_observation()
		.expect("ordinary reads may advance atime without invalidating the observation");
	assert_eq!(source.observation(), observation);
}

#[test]
fn rejects_observed_mode_and_size_changes_through_the_same_inode() {
	let scratch = Scratch::new();
	for (name, replace_metadata) in [("mode", true), ("size", false)] {
		let path = scratch.path(name);
		let writer = File::create(&path).expect("create source fixture");
		writer.set_len(3).expect("set initial source length");
		writer
			.set_permissions(Permissions::from_mode(0o600))
			.expect("set initial source permissions");
		let root = ReadRoot::from_directory(scratch.open()).expect("admit source root");
		let source = root
			.open_regular(UnixComponent::new(name.as_bytes()).expect("valid name"))
			.expect("open source file");
		if replace_metadata {
			writer
				.set_permissions(Permissions::from_mode(0o640))
				.expect("change mode on the held inode");
		} else {
			writer.set_len(2).expect("shrink the held inode");
		}
		assert!(matches!(
			source.recheck_observation(),
			Err(ReadError::SourceChanged)
		));
	}
}

#[test]
fn rejects_a_same_size_write_with_an_observed_modification_time_change() {
	let scratch = Scratch::new();
	let writer = File::create(scratch.path(SOURCE)).expect("create source fixture");
	writer.write_all_at(b"old", 0).expect("write initial bytes");
	writer
		.set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(100)))
		.expect("set initial modification time");
	let root = ReadRoot::from_directory(scratch.open()).expect("admit source root");
	let source = root
		.open_regular(UnixComponent::new(SOURCE.as_bytes()).expect("valid name"))
		.expect("open source file");
	writer
		.write_all_at(b"new", 0)
		.expect("overwrite with the same length");
	writer
		.set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(200)))
		.expect("set changed modification time");
	assert_eq!(
		writer.metadata().expect("inspect changed file").len(),
		source.len()
	);
	assert!(matches!(
		source.recheck_observation(),
		Err(ReadError::SourceChanged)
	));
}

#[test]
fn queries_visible_attribute_names_on_the_held_source_inode() {
	let scratch = Scratch::new();
	let path = scratch.path(SOURCE);
	let writer = File::create(&path).expect("create source fixture");
	let root = ReadRoot::from_directory(scratch.open()).expect("admit source root");
	let source = root
		.open_regular(UnixComponent::new(SOURCE.as_bytes()).expect("valid name"))
		.expect("open source file");
	let visible_bytes = unix::flistxattr_query(&writer).expect("query native fixture xattrs");
	let expected = if visible_bytes == 0 {
		ExtendedAttributes::NoneVisible
	} else {
		ExtendedAttributes::Present
	};
	assert_eq!(
		source.extended_attributes().expect("inspect names"),
		expected
	);
	fs::rename(&path, scratch.path("moved")).expect("move source fixture");
	fs::write(&path, b"replacement").expect("replace its name");
	unix::fsetxattr(
		&writer,
		c"user.exacopy_test",
		b"fixture",
		XattrFlags::CREATE,
	)
	.expect("attach a visible attribute to the original inode");
	assert_eq!(
		source.extended_attributes().expect("inspect the held file"),
		ExtendedAttributes::Present,
	);
}
