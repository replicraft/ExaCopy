use std::fs::{self, File};
use std::os::unix::fs::symlink;
use std::process::Command;

use exacopy_endpoint::UnixComponent;

use super::{ProbeError, ReadRoot, RegularFileProbe};
use crate::scratch::Scratch;

fn probe(root: &ReadRoot, name: &[u8]) -> RegularFileProbe {
	root.probe_regular_file(UnixComponent::new(name).expect("literal child name"))
		.expect("inspect synthetic child")
}

#[test]
fn refuses_to_bind_regular_file_as_a_directory() {
	let fixture = Scratch::new();
	let file = File::create_new(fixture.path("file")).expect("create synthetic file");
	assert!(matches!(
		ReadRoot::from_directory(file),
		Err(ProbeError::NotDirectory)
	));
}

#[test]
fn observing_regular_metadata_does_not_authorize_read_open() {
	let fixture = Scratch::new();
	let path = fixture.path("source");
	fs::write(&path, b"unchanged").expect("create synthetic source");
	let root = ReadRoot::from_directory(fixture.open()).expect("bind synthetic directory");

	assert_eq!(
		probe(&root, b"source"),
		RegularFileProbe::PinnedReadOpenUnavailable
	);
	assert_eq!(
		fs::read(path).expect("read synthetic fixture"),
		b"unchanged"
	);
	fixture.assert_debug_redacts(&root, &["source"]);
}

#[test]
fn probes_links_without_following_and_refuses_nonregular_children() {
	let fixture = Scratch::new();
	fs::write(fixture.path("source"), b"data").expect("create synthetic source");
	symlink("source", fixture.path("link")).expect("create synthetic symlink");
	symlink("missing", fixture.path("dangling")).expect("create synthetic dangling link");
	fs::create_dir(fixture.path("directory")).expect("create synthetic subdirectory");
	assert!(
		Command::new("/usr/bin/mkfifo")
			.arg(fixture.path("fifo"))
			.status()
			.expect("run native fixture creation")
			.success()
	);
	let root = ReadRoot::from_directory(fixture.open()).expect("bind synthetic directory");

	assert_eq!(probe(&root, b"link"), RegularFileProbe::SymbolicLink);
	assert_eq!(probe(&root, b"dangling"), RegularFileProbe::SymbolicLink);
	assert_eq!(probe(&root, b"directory"), RegularFileProbe::NotRegularFile);
	assert_eq!(probe(&root, b"fifo"), RegularFileProbe::NotRegularFile);
	assert_eq!(probe(&root, b"missing"), RegularFileProbe::Missing);
}

#[test]
fn resolves_against_the_held_directory_after_its_path_is_replaced() {
	let fixture = Scratch::new();
	let original = fixture.path("original");
	let moved = fixture.path("moved");
	fs::create_dir(&original).expect("create original directory");
	fs::write(original.join("child"), b"data").expect("create original child");
	let root = ReadRoot::from_directory(File::open(&original).expect("open original directory"))
		.expect("bind original directory");
	fs::rename(&original, moved).expect("rename original directory");
	fs::create_dir(&original).expect("create replacement directory");
	symlink("missing", original.join("child")).expect("create replacement symlink");

	assert_eq!(
		probe(&root, b"child"),
		RegularFileProbe::PinnedReadOpenUnavailable
	);
}

#[test]
fn an_earlier_regular_observation_does_not_follow_a_replacement_link() {
	let fixture = Scratch::new();
	let child = fixture.path("child");
	fs::write(&child, b"data").expect("create synthetic file");
	let root = ReadRoot::from_directory(fixture.open()).expect("bind synthetic directory");
	assert_eq!(
		probe(&root, b"child"),
		RegularFileProbe::PinnedReadOpenUnavailable
	);

	fs::rename(&child, fixture.path("moved")).expect("move original child");
	symlink("moved", child).expect("install replacement symlink");
	assert_eq!(probe(&root, b"child"), RegularFileProbe::SymbolicLink);
}
