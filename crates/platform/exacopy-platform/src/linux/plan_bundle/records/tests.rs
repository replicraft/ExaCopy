use std::fs as std_fs;
use std::os::unix::fs::{MetadataExt as _, symlink};

use super::*;
use crate::scratch::Scratch;

#[test]
fn existing_page_is_reused_only_when_its_private_bytes_match() {
	let scratch = Scratch::new();
	let parent = scratch.open();
	let name = UnixComponent::new(b"page").unwrap();
	let record = create(&parent, name, b"exact").unwrap();
	let original = std_fs::metadata(scratch.path("page")).unwrap();
	assert!(
		create(&parent, name, b"other")
			.err()
			.unwrap()
			.is_existing_name()
	);
	let reused = read_existing(&parent, name, b"exact", &mut [0; 5]).unwrap();
	check_named(&parent, name, &reused).unwrap();
	assert!(read_existing(&parent, name, b"other", &mut [0; 5]).is_err());
	let current = std_fs::metadata(scratch.path("page")).unwrap();
	assert_eq!(current.ino(), original.ino());
	assert_eq!(std_fs::read(scratch.path("page")).unwrap(), b"exact");
	check_named(&parent, name, &record).unwrap();
}

#[test]
fn hard_link_and_symlink_incumbents_are_never_adopted_as_pages() {
	let scratch = Scratch::new();
	let parent = scratch.open();
	let original = UnixComponent::new(b"incumbent").unwrap();
	create(&parent, original, b"exact").unwrap();
	std_fs::hard_link(scratch.path("incumbent"), scratch.path("hard")).unwrap();
	symlink(scratch.path("incumbent"), scratch.path("soft")).unwrap();
	for name in ["hard", "soft"] {
		let name = UnixComponent::new(name.as_bytes()).unwrap();
		assert!(
			create(&parent, name, b"replace")
				.err()
				.unwrap()
				.is_existing_name()
		);
		assert!(read_existing(&parent, name, b"exact", &mut [0; 5]).is_err());
	}
	assert_eq!(std_fs::read(scratch.path("incumbent")).unwrap(), b"exact");
}
