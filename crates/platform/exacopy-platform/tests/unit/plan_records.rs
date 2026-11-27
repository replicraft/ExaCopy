use std::fs as std_fs;
use std::fs::File;
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::MetadataExt as _;

use exacopy_endpoint::UnixComponent;

use super::{PlanBundleError, check_named, create, read_existing};
use crate::scratch::Scratch;

#[test]
fn exclusive_create_refuses_a_detached_parent() {
	let scratch = Scratch::new();
	let detached = scratch.path("detached");
	let incumbent = scratch.path("page");
	std_fs::create_dir(&detached).expect("create empty fixture directory");
	std_fs::write(&incumbent, b"incumbent").expect("create sibling fixture page");
	let parent = File::open(&detached).expect("hold fixture directory");
	std_fs::remove_dir(&detached).expect("detach the empty fixture directory");
	let name = UnixComponent::new(b"page").expect("validate fixture page name");

	assert!(
		matches!(
			create(&parent, name, b"candidate"),
			Err(PlanBundleError::Io(error)) if error.kind() == ErrorKind::NotFound
		),
		"a detached parent must report a native creation failure"
	);
	assert_eq!(
		std_fs::symlink_metadata(&detached)
			.expect_err("fixture name must remain absent")
			.kind(),
		ErrorKind::NotFound
	);
	assert_eq!(
		std_fs::read(&incumbent).expect("read sibling fixture page"),
		b"incumbent"
	);
}

#[test]
fn page_reuse_requires_scratch_of_the_exact_length() {
	let scratch = Scratch::new();
	let parent = scratch.open();
	let name = UnixComponent::new(b"page").expect("validate fixture page name");
	let record = create(&parent, name, b"exact").expect("create private fixture page");
	let mut bytes = *b"keep";

	assert!(
		matches!(
			read_existing(&parent, name, b"exact", &mut bytes),
			Err(PlanBundleError::Conflict)
		),
		"an undersized buffer must be refused before reading the page"
	);
	assert_eq!(bytes, *b"keep");
	assert_eq!(
		std_fs::read(scratch.path("page")).expect("read private fixture page"),
		b"exact"
	);
	check_named(&parent, name, &record).expect("retain the original page identity");
}

#[test]
fn page_recheck_refuses_a_changed_held_file() {
	let scratch = Scratch::new();
	let parent = scratch.open();
	let name = UnixComponent::new(b"page").expect("validate fixture page name");
	let path = scratch.path("page");
	let record = create(&parent, name, b"exact").expect("create private fixture page");
	let original = std_fs::metadata(&path).expect("observe original fixture inode");
	let mut writer = std_fs::OpenOptions::new()
		.append(true)
		.open(&path)
		.expect("open fixture page for append");
	writer
		.write_all(b" extended")
		.expect("append to fixture page");
	drop(writer);

	assert!(
		matches!(
			check_named(&parent, name, &record),
			Err(PlanBundleError::Conflict)
		),
		"the original held observation must expire when its file changes"
	);
	assert_eq!(
		std_fs::metadata(&path)
			.expect("observe fixture inode after refusal")
			.ino(),
		original.ino()
	);
	assert_eq!(
		std_fs::read(&path).expect("read fixture page after refusal"),
		b"exact extended"
	);
}

#[test]
fn page_recheck_refuses_a_different_inode_with_identical_bytes() {
	let scratch = Scratch::new();
	let parent = scratch.open();
	let original_name = UnixComponent::new(b"original").expect("validate original fixture name");
	let other_name = UnixComponent::new(b"other").expect("validate second fixture name");
	let original = create(&parent, original_name, b"exact").expect("create original fixture page");
	let other = create(&parent, other_name, b"exact").expect("create independent fixture page");
	let original_path = scratch.path("original");
	let other_path = scratch.path("other");
	let original_inode = std_fs::metadata(&original_path)
		.expect("observe original inode")
		.ino();
	let other_inode = std_fs::metadata(&other_path)
		.expect("observe second inode")
		.ino();
	assert_ne!(
		original_inode, other_inode,
		"the pages must be independent fixtures"
	);

	assert!(
		matches!(
			check_named(&parent, other_name, &original),
			Err(PlanBundleError::Conflict)
		),
		"matching page bytes cannot substitute for the held identity"
	);
	check_named(&parent, original_name, &original).expect("retain original record binding");
	check_named(&parent, other_name, &other).expect("retain second record binding");
	assert_eq!(
		std_fs::read(&original_path).expect("read original fixture page"),
		b"exact"
	);
	assert_eq!(
		std_fs::read(&other_path).expect("read second fixture page"),
		b"exact"
	);
}
