//! Native fixed-scope checks for manually selected read-only workflow artifacts.

#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt as _, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use exacopy_endpoint::UnixComponent;
use exacopy_platform::linux::{
	ReadError, ReadRoot, SyncHistoryDirectory, SyncPreviewError, SyncPreviewRoots,
};

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
	fn new() -> Self {
		let next = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
		let path = PathBuf::from("/dev/shm").join(format!(
			"exacopy-sync-history-{}-{next}",
			std::process::id()
		));
		fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
		Self(path)
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

fn name(raw: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(raw).unwrap()
}

#[test]
fn explicit_member_names_borrow_stable_bounded_read_only_views() {
	let fixture = Fixture::new();
	let artifact = fixture.0.join("selected");
	let sibling = fixture.0.join("other");
	fs::write(&artifact, b"valid").unwrap();
	fs::write(&sibling, b"other").unwrap();
	symlink("other", fixture.0.join("alias")).unwrap();
	let root = ReadRoot::from_directory(File::open(&fixture.0).unwrap()).unwrap();
	let directory = SyncHistoryDirectory::new(&root, 5);

	let mut reader = directory.open_member(name(b"selected")).unwrap();
	let mut content = Vec::new();
	reader.read_to_end(&mut content).unwrap();
	assert_eq!(content, b"valid");
	assert_eq!(
		directory.open_member(name(b"missing")).unwrap_err().kind(),
		io::ErrorKind::NotFound
	);
	assert!(directory.open_member(name(b"alias")).is_err());
	assert!(
		SyncHistoryDirectory::new(&root, 4)
			.open_member(name(b"selected"))
			.is_err()
	);

	let mut reader = directory.open_member(name(b"selected")).unwrap();
	let mut bytes = [0; 5];
	reader.read_exact(&mut bytes).unwrap();
	fs::rename(&artifact, fixture.0.join("retained")).unwrap();
	fs::write(&artifact, b"newer").unwrap();
	assert!(
		reader.read(&mut [0]).is_err(),
		"EOF must recheck the held name"
	);
	assert_eq!(fs::read(sibling).unwrap(), b"other");
}

#[test]
fn empty_reads_preserve_position_and_nonempty_eof_refuses_member_growth() {
	let fixture = Fixture::new();
	let artifact = fixture.0.join("selected");
	fs::write(&artifact, b"valid").unwrap();
	let root = ReadRoot::from_directory(File::open(&fixture.0).unwrap()).unwrap();
	let directory = SyncHistoryDirectory::new(&root, 5);
	let mut reader = directory.open_member(name(b"selected")).unwrap();

	assert_eq!(reader.read(&mut []).unwrap(), 0);
	let mut content = [0; 5];
	reader.read_exact(&mut content).unwrap();
	assert_eq!(&content, b"valid");

	File::options()
		.append(true)
		.open(&artifact)
		.unwrap()
		.write_all(b"x")
		.unwrap();

	let mut probe = [0];
	let error = reader.read(&mut probe).unwrap_err();
	assert_eq!(error.kind(), io::ErrorKind::Other);
	let cause = error
		.get_ref()
		.expect("member EOF refusal has a typed cause");
	assert!(matches!(
		cause.downcast_ref::<ReadError>(),
		Some(ReadError::SourceChanged)
	));
	assert_eq!(probe, [0]);
	assert_eq!(fs::read(artifact).unwrap(), b"validx");
}

#[test]
fn tmpfs_live_preview_scope_does_not_become_historical_ext4_evidence() {
	let fixture = Fixture::new();
	fs::create_dir(fixture.0.join("left")).unwrap();
	fs::create_dir(fixture.0.join("right")).unwrap();
	let roots = SyncPreviewRoots::open(&fixture.0, [name(b"left"), name(b"right")]).unwrap();
	let pair = roots.observe(name(b"subject")).unwrap();
	assert!(matches!(
		pair.recheck_history_location(),
		Err(SyncPreviewError::UnsupportedMount)
	));
}
