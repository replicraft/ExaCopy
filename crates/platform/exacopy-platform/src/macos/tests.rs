use std::error::Error as _;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{PermissionsExt as _, symlink};
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

#[test]
fn an_inaccessible_lookup_is_a_system_failure_instead_of_a_missing_child() {
	let fixture = Scratch::new();
	let directory = fixture.path("restricted");
	fs::create_dir(&directory).expect("create a privately controlled probe directory");
	let child = directory.join("child");
	fs::write(&child, b"retain these bytes").expect("write the existing child");
	let root = ReadRoot::from_directory(File::open(&directory).expect("open directory first"))
		.expect("bind a held directory for relative probes");
	let permissions = fs::metadata(&directory)
		.expect("capture fixture permissions")
		.permissions();
	fs::set_permissions(&directory, fs::Permissions::from_mode(0o600))
		.expect("deny child lookup by removing search access");
	let component = UnixComponent::new(b"child").expect("represent a valid child");
	let result = root.probe_regular_file(component);
	fs::set_permissions(&directory, permissions)
		.expect("restore synthetic directory search access");

	let failure = result.expect_err("an inconclusive lookup must not report absence");
	assert!(
		matches!(&failure, ProbeError::System(error) if error.kind() == io::ErrorKind::PermissionDenied)
	);
	let cause = failure
		.source()
		.and_then(|cause| cause.downcast_ref::<io::Error>())
		.expect("retain the typed native lookup failure");
	assert_eq!(cause.raw_os_error(), Some(libc::EACCES));
	assert!(failure.to_string().contains("metadata probe failed"));
	assert_eq!(
		probe(&root, b"child"),
		RegularFileProbe::PinnedReadOpenUnavailable
	);
	assert_eq!(
		fs::read(&child).expect("inspect existing child"),
		b"retain these bytes"
	);
}
