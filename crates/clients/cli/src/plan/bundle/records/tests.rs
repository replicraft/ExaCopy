use std::fs::{self as std_fs, DirBuilder};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, symlink};
use std::path::PathBuf;

use super::*;

struct Scratch(PathBuf);

impl Scratch {
	fn new() -> Self {
		let mut random = [0; 16];
		crate::profile::kernel_random(&mut random).unwrap();
		let path =
			std::env::temp_dir().join(format!("plan-export-{}", uuid::Uuid::from_bytes(random)));
		DirBuilder::new().mode(0o700).create(&path).unwrap();
		Self(path)
	}
}

impl Drop for Scratch {
	fn drop(&mut self) {
		let _ = std_fs::remove_dir_all(&self.0);
	}
}

#[test]
fn existing_page_is_reused_only_when_its_private_bytes_match() {
	let scratch = Scratch::new();
	let parent = File::open(&scratch.0).unwrap();
	let name = UnixComponent::new(b"page").unwrap();
	let record = create(&parent, name, b"exact").unwrap();
	let original = std_fs::metadata(scratch.0.join("page")).unwrap();
	assert!(
		create(&parent, name, b"other")
			.err()
			.unwrap()
			.is_existing_name()
	);
	let reused = read_existing(&parent, name, b"exact").unwrap();
	check_named(&parent, name, &reused).unwrap();
	assert!(read_existing(&parent, name, b"other").is_err());
	let current = std_fs::metadata(scratch.0.join("page")).unwrap();
	assert_eq!(current.ino(), original.ino());
	assert_eq!(std_fs::read(scratch.0.join("page")).unwrap(), b"exact");
	check_named(&parent, name, &record).unwrap();
}

#[test]
fn hard_link_and_symlink_incumbents_are_never_adopted_as_pages() {
	let scratch = Scratch::new();
	let parent = File::open(&scratch.0).unwrap();
	let original = UnixComponent::new(b"incumbent").unwrap();
	create(&parent, original, b"exact").unwrap();
	std_fs::hard_link(scratch.0.join("incumbent"), scratch.0.join("hard")).unwrap();
	symlink(scratch.0.join("incumbent"), scratch.0.join("soft")).unwrap();
	for name in ["hard", "soft"] {
		let name = UnixComponent::new(name.as_bytes()).unwrap();
		assert!(
			create(&parent, name, b"replace")
				.err()
				.unwrap()
				.is_existing_name()
		);
		assert!(read_existing(&parent, name, b"exact").is_err());
	}
	assert_eq!(std_fs::read(scratch.0.join("incumbent")).unwrap(), b"exact");
}
