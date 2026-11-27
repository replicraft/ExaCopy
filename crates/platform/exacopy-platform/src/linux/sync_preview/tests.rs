use std::fs;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

const TEST_PARENT: &str = "/dev/shm";
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
	fn new() -> Self {
		let case = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
		let path =
			Path::new(TEST_PARENT).join(format!("exacopy-sync-{}-{case}", std::process::id()));
		fs::DirBuilder::new()
			.mode(0o700)
			.create(&path)
			.expect("create private test scope on Linux tmpfs");
		let fixture = Self(path);
		fs::create_dir(fixture.0.join("left")).unwrap();
		fs::create_dir(fixture.0.join("right")).unwrap();
		fixture
	}

	fn roots(&self) -> SyncPreviewRoots<'_> {
		SyncPreviewRoots::open(&self.0, [component(b"left"), component(b"right")]).unwrap()
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

fn component(bytes: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(bytes).unwrap()
}

#[test]
fn recheck_rejects_absent_name_that_appears_and_rebound_root() {
	let fixture = Fixture::new();
	let roots = fixture.roots();
	let scope = roots.observe(component(b"file")).unwrap();
	assert!(matches!(
		scope.entries(),
		[SyncPreviewEntry::Absent, SyncPreviewEntry::Absent]
	));
	fs::write(fixture.0.join("right/file"), b"late appearance").unwrap();
	assert!(matches!(scope.recheck(), Err(SyncPreviewError::Changed)));
	let scope = roots.observe(component(b"file")).unwrap();
	fs::rename(fixture.0.join("right"), fixture.0.join("old-right")).unwrap();
	fs::create_dir(fixture.0.join("right")).unwrap();
	assert!(matches!(scope.recheck(), Err(SyncPreviewError::Changed)));
}

#[test]
fn recheck_rejects_changed_bytes_and_required_metadata() {
	use std::os::unix::fs::PermissionsExt as _;

	let fixture = Fixture::new();
	let target = fixture.0.join("left/file");
	fs::write(&target, b"one").unwrap();
	let roots = fixture.roots();
	let scope = roots.observe(component(b"file")).unwrap();
	fs::set_permissions(&target, fs::Permissions::from_mode(0o400)).unwrap();
	assert!(matches!(scope.recheck(), Err(SyncPreviewError::Changed)));
	fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
	let scope = roots.observe(component(b"file")).unwrap();
	fs::write(&target, b"two with changed length").unwrap();
	assert!(matches!(scope.recheck(), Err(SyncPreviewError::Changed)));
}

#[test]
fn unsupported_and_aliased_subjects_never_become_absence() {
	use std::os::unix::fs::symlink;

	let fixture = Fixture::new();
	fs::write(fixture.0.join("left/file"), b"left bytes").unwrap();
	symlink("../left/file", fixture.0.join("right/file")).unwrap();
	let roots = fixture.roots();
	let scope = roots.observe(component(b"file")).unwrap();
	assert!(matches!(
		scope.entries(),
		[SyncPreviewEntry::Present(_), SyncPreviewEntry::Unsupported]
	));
	scope.recheck().unwrap();
	fs::remove_file(fixture.0.join("right/file")).unwrap();
	fs::hard_link(fixture.0.join("left/file"), fixture.0.join("right/file")).unwrap();
	assert!(matches!(
		roots.observe(component(b"file")),
		Err(SyncPreviewError::AliasedFiles)
	));
}

#[test]
fn matching_inode_cannot_substitute_a_different_raw_name() {
	let fixture = Fixture::new();
	fs::write(fixture.0.join("left/Report"), b"existing bytes").unwrap();
	let roots = fixture.roots();
	let root = &roots.roots[0];
	let pinned = pin(root, component(b"Report")).unwrap().unwrap();
	let identity = FileIdentity::from_stat(&rustix::fs::fstat(&pinned).unwrap());
	assert!(matches!(
		names::confirm(root.directory(), component(b"report"), Some(identity)),
		Err(SyncPreviewError::NameAlias)
	));
}

#[test]
fn a_bounded_directory_scan_cannot_certify_absence_when_exhausted() {
	let fixture = Fixture::new();
	let path = fixture.0.join("left");
	for index in 0..names::MAX_DIRECTORY_ENTRIES {
		fs::File::create(path.join(index.to_string())).unwrap();
	}
	let roots = fixture.roots();
	assert!(matches!(
		roots.observe(component(b"unobserved-name")),
		Err(SyncPreviewError::DirectoryLimit)
	));
}

#[test]
fn recheck_returns_ordered_fresh_present_stats_and_refuses_a_rebound_subject() {
	let fixture = Fixture::new();
	let left_path = fixture.0.join("left/file");
	let right_path = fixture.0.join("right/file");
	fs::write(&left_path, b"left").unwrap();
	fs::write(&right_path, b"right").unwrap();
	let roots = fixture.roots();
	let pair = roots.observe(component(b"file")).unwrap();

	let [left, right] = pair.recheck_subjects().unwrap();
	for (fact, path) in [(left, &left_path), (right, &right_path)] {
		let stat = fs::File::open(path).unwrap();
		let stat = rustix::fs::fstat(stat).unwrap();
		assert_eq!(fact, Some(SourceObservation::capture(&stat).unwrap()));
	}

	fs::rename(&right_path, fixture.0.join("right/retained")).unwrap();
	fs::write(&right_path, b"right").unwrap();
	assert!(matches!(
		pair.recheck_subjects(),
		Err(SyncPreviewError::Changed)
	));
	assert!(matches!(pair.recheck(), Err(SyncPreviewError::Changed)));
}
