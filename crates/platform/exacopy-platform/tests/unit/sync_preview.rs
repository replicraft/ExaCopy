use std::error::Error as _;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};

use exacopy_endpoint::{ReadView as _, UnixComponent};
use rustix::io::Errno;

use super::super::{
	MAX_PARENT_PATH_BYTES, ReadError, SyncPreviewEntry, SyncPreviewError, SyncPreviewRoots,
};
use super::{Fixture, component};

fn assert_diagnostic(error: &SyncPreviewError, explanation: &str) {
	assert!(
		error.to_string().contains(explanation),
		"missing explanation {explanation:?} in {error}"
	);
	assert!(error.source().is_none(), "{error:?} has a spurious cause");
}

fn assert_system_cause(error: &SyncPreviewError, expected: Errno) {
	assert!(matches!(error, SyncPreviewError::System(_)), "{error:?}");
	let cause = error
		.source()
		.and_then(|cause| cause.downcast_ref::<io::Error>())
		.expect("preview system failure retains the native error");
	assert_eq!(cause.raw_os_error(), Some(expected.raw_os_error()));
	assert_eq!(error.to_string(), cause.to_string());
}

struct RestrictedDirectory {
	directory: fs::File,
	original: fs::Permissions,
}

impl RestrictedDirectory {
	fn with_mode(path: &Path, mode: u32) -> Self {
		let directory = fs::File::open(path).expect("hold owned directory before restriction");
		let original = directory.metadata().unwrap().permissions();
		directory
			.set_permissions(fs::Permissions::from_mode(mode))
			.unwrap();
		Self {
			directory,
			original,
		}
	}
}

impl Drop for RestrictedDirectory {
	fn drop(&mut self) {
		self.directory
			.set_permissions(self.original.clone())
			.expect("restore fixture permissions before cleanup");
	}
}

fn root_names() -> [UnixComponent<'static>; 2] {
	[component(b"left"), component(b"right")]
}

#[test]
fn selection_rejects_invalid_parent_paths_and_duplicate_root_names() {
	let fixture = Fixture::new();
	let left = fixture.0.join("left/file");
	let right = fixture.0.join("right/file");
	fs::write(&left, b"source").unwrap();
	fs::write(&right, b"incumbent").unwrap();

	for path in [
		PathBuf::from("relative"),
		PathBuf::from(format!("/{}", "x".repeat(MAX_PARENT_PATH_BYTES))),
		fixture.0.join("left/../right"),
		fixture.0.join("./left"),
		fixture.0.join("left//right"),
		fixture.0.join("left/"),
	] {
		let error = SyncPreviewRoots::open(&path, root_names()).unwrap_err();
		assert!(
			matches!(error, SyncPreviewError::InvalidParent),
			"{path:?}: {error:?}"
		);
		assert_diagnostic(&error, "invalid absolute sync parent");
	}

	let error = SyncPreviewRoots::open(&fixture.0, [component(b"right"); 2]).unwrap_err();
	assert!(matches!(error, SyncPreviewError::AliasedRoots));
	assert_diagnostic(&error, "distinct directories");
	assert_eq!(fs::read(left).unwrap(), b"source");
	assert_eq!(fs::read(right).unwrap(), b"incumbent");
}

#[test]
fn selection_rejects_symlinked_parents_and_children_and_retains_native_causes() {
	let fixture = Fixture::new();
	let left = fixture.0.join("left");
	let right = fixture.0.join("right");
	let target = right.join("file");
	fs::write(&target, b"incumbent").unwrap();

	let parent_link = left.join("linked-parent");
	symlink(&fixture.0, &parent_link).unwrap();
	let error = SyncPreviewRoots::open(&parent_link, root_names()).unwrap_err();
	assert_system_cause(&error, Errno::LOOP);

	let error = SyncPreviewRoots::open(&fixture.0, [component(b"left"), component(b"missing")])
		.unwrap_err();
	assert_system_cause(&error, Errno::NOENT);

	let child_link = fixture.0.join("linked-child");
	symlink("right", &child_link).unwrap();
	let error =
		SyncPreviewRoots::open(&fixture.0, [component(b"left"), component(b"linked-child")])
			.unwrap_err();
	assert_system_cause(&error, Errno::LOOP);

	assert_eq!(fs::read_link(parent_link).unwrap(), fixture.0);
	assert_eq!(fs::read_link(child_link).unwrap(), Path::new("right"));
	assert_eq!(fs::read(target).unwrap(), b"incumbent");
}

#[test]
fn selection_refuses_procfs_as_an_unsupported_mount() {
	let error = SyncPreviewRoots::open(Path::new("/proc"), root_names()).unwrap_err();
	assert!(matches!(error, SyncPreviewError::UnsupportedMount));
	assert_diagnostic(&error, "whole local");
}

#[test]
fn selection_and_recheck_keep_raw_names_ordered_and_preserve_both_files() {
	let fixture = Fixture::new();
	let name = b"report-\xff";
	let name_on_disk = OsStr::from_bytes(name);
	let left_root = fixture.0.join("left");
	let right_root = fixture.0.join("right");
	let left = left_root.join(name_on_disk);
	let right = right_root.join(name_on_disk);
	fs::write(&left, b"source").unwrap();
	fs::write(&right, b"incumbent").unwrap();
	fs::set_permissions(&left, fs::Permissions::from_mode(0o640)).unwrap();
	fs::set_permissions(&right, fs::Permissions::from_mode(0o600)).unwrap();
	let left_before = fs::symlink_metadata(&left).unwrap();
	let right_before = fs::symlink_metadata(&right).unwrap();
	let roots = fixture.roots();
	let selection = roots.selection();
	assert_ne!(
		selection.mount_id, 0,
		"selected mount has a live identifier"
	);
	for (path, identity) in [
		(&fixture.0, selection.parent),
		(&left_root, selection.roots[0]),
		(&right_root, selection.roots[1]),
	] {
		let metadata = fs::metadata(path).unwrap();
		assert_eq!(
			(identity.device(), identity.inode()),
			(metadata.dev(), metadata.ino())
		);
	}

	let pair = roots.observe(component(name)).unwrap();
	let [
		SyncPreviewEntry::Present(left_view),
		SyncPreviewEntry::Present(right_view),
	] = pair.entries()
	else {
		panic!("both raw names must select present regular files");
	};
	let mut source = [0; b"source".len()];
	let mut incumbent = [0; b"incumbent".len()];
	left_view.read_exact_at(0, &mut source).unwrap();
	right_view.read_exact_at(0, &mut incumbent).unwrap();
	assert_eq!(&source, b"source");
	assert_eq!(&incumbent, b"incumbent");

	let error = left_view
		.read_exact_at(left_view.length(), &mut [0])
		.map_err(SyncPreviewError::from)
		.unwrap_err();
	assert!(matches!(
		error,
		SyncPreviewError::Read(ReadError::RangeOutsideFile)
	));
	let cause = error
		.source()
		.and_then(|cause| cause.downcast_ref::<ReadError>())
		.expect("read error retains its cause");
	assert!(matches!(cause, ReadError::RangeOutsideFile));
	assert_eq!(error.to_string(), cause.to_string());

	pair.recheck().unwrap();
	for (root, path, identity, bytes, before) in [
		(
			&left_root,
			&left,
			left_view.identity(),
			&b"source"[..],
			left_before,
		),
		(
			&right_root,
			&right,
			right_view.identity(),
			&b"incumbent"[..],
			right_before,
		),
	] {
		let expected_identity = (before.dev(), before.ino());
		let metadata = fs::symlink_metadata(path).unwrap();
		assert_eq!((identity.device(), identity.inode()), expected_identity);
		assert_eq!((metadata.dev(), metadata.ino()), expected_identity);
		assert_eq!(metadata.mode(), before.mode());
		assert_eq!(metadata.nlink(), 1);
		assert_eq!(fs::read(path).unwrap(), bytes);
		let names: Vec<_> = fs::read_dir(root)
			.unwrap()
			.map(|entry| entry.unwrap().file_name())
			.collect();
		assert_eq!(names, [name_on_disk.to_os_string()]);
	}
}

#[test]
fn recheck_refuses_disappeared_linked_and_rebound_parents() {
	let fixture = Fixture::new();
	let selected = fixture.0.join("selected");
	let retained = fixture.0.join("retained");
	fs::create_dir(&selected).unwrap();
	fs::create_dir(selected.join("left")).unwrap();
	fs::create_dir(selected.join("right")).unwrap();
	fs::write(selected.join("left/file"), b"source").unwrap();
	fs::write(selected.join("right/file"), b"incumbent").unwrap();
	let roots = SyncPreviewRoots::open(&selected, root_names()).unwrap();
	let pair = roots.observe(component(b"file")).unwrap();

	fs::rename(&selected, &retained).unwrap();
	let error = pair.recheck().unwrap_err();
	assert!(matches!(error, SyncPreviewError::Changed));
	assert_diagnostic(&error, "scope changed");

	symlink(&retained, &selected).unwrap();
	assert!(matches!(pair.recheck(), Err(SyncPreviewError::Changed)));
	assert_eq!(fs::read_link(&selected).unwrap(), retained);

	fs::remove_file(&selected).unwrap();
	fs::create_dir(&selected).unwrap();
	fs::create_dir(selected.join("left")).unwrap();
	fs::create_dir(selected.join("right")).unwrap();
	fs::write(selected.join("right/file"), b"new incumbent").unwrap();
	assert!(matches!(pair.recheck(), Err(SyncPreviewError::Changed)));
	assert_eq!(fs::read(retained.join("left/file")).unwrap(), b"source");
	assert_eq!(fs::read(retained.join("right/file")).unwrap(), b"incumbent");
	assert_eq!(
		fs::read(selected.join("right/file")).unwrap(),
		b"new incumbent"
	);
}

#[test]
fn recheck_refuses_a_disappeared_or_symlinked_child_root() {
	let fixture = Fixture::new();
	let right = fixture.0.join("right");
	let retained = fixture.0.join("retained");
	fs::write(fixture.0.join("left/file"), b"source").unwrap();
	fs::write(right.join("file"), b"incumbent").unwrap();
	let roots = fixture.roots();
	let pair = roots.observe(component(b"file")).unwrap();

	fs::rename(&right, &retained).unwrap();
	assert!(matches!(pair.recheck(), Err(SyncPreviewError::Changed)));
	symlink("retained", &right).unwrap();
	assert!(matches!(pair.recheck(), Err(SyncPreviewError::Changed)));
	assert_eq!(fs::read_link(right).unwrap(), Path::new("retained"));
	assert_eq!(fs::read(fixture.0.join("left/file")).unwrap(), b"source");
	assert_eq!(fs::read(retained.join("file")).unwrap(), b"incumbent");
}

#[test]
fn recheck_rejects_changed_or_disappeared_unsupported_entries() {
	let fixture = Fixture::new();
	let left = fixture.0.join("left/file");
	let right = fixture.0.join("right/file");
	let retained = fixture.0.join("right/retained");
	fs::write(&left, b"source").unwrap();
	fs::create_dir(&right).unwrap();
	fs::set_permissions(&right, fs::Permissions::from_mode(0o700)).unwrap();
	fs::write(right.join("incumbent"), b"inside unsupported directory").unwrap();
	let roots = fixture.roots();
	let pair = roots.observe(component(b"file")).unwrap();
	assert!(matches!(
		pair.entries(),
		[SyncPreviewEntry::Present(_), SyncPreviewEntry::Unsupported]
	));
	pair.recheck().unwrap();

	fs::set_permissions(&right, fs::Permissions::from_mode(0o750)).unwrap();
	assert!(matches!(pair.recheck(), Err(SyncPreviewError::Changed)));
	let pair = roots.observe(component(b"file")).unwrap();
	pair.recheck().unwrap();
	fs::rename(&right, &retained).unwrap();
	assert!(matches!(pair.recheck(), Err(SyncPreviewError::Changed)));

	assert_eq!(fs::read(left).unwrap(), b"source");
	assert_eq!(
		fs::symlink_metadata(&retained).unwrap().mode() & 0o777,
		0o750
	);
	assert_eq!(
		fs::read(retained.join("incumbent")).unwrap(),
		b"inside unsupported directory"
	);
}

#[test]
fn access_denial_remains_a_system_error_instead_of_a_changed_or_absent_entry() {
	let fixture = Fixture::new();
	let left = fixture.0.join("left/file");
	let right = fixture.0.join("right");
	let right_file = right.join("file");
	fs::write(&left, b"source").unwrap();
	fs::write(&right_file, b"incumbent").unwrap();
	let roots = fixture.roots();
	let pair = roots.observe(component(b"file")).unwrap();

	let (parent_read, parent_recheck) = {
		let _restricted = RestrictedDirectory::with_mode(&fixture.0, 0o300);
		(fs::read_dir(&fixture.0), pair.recheck())
	};
	match parent_read {
		Ok(_) => parent_recheck.unwrap(),
		Err(error) => {
			assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
			assert_system_cause(&parent_recheck.unwrap_err(), Errno::ACCESS);
		}
	}

	let (subject_lookup, observation) = {
		let _restricted = RestrictedDirectory::with_mode(&right, 0o600);
		(
			fs::symlink_metadata(&right_file),
			roots.observe(component(b"file")),
		)
	};
	match subject_lookup {
		Ok(_) => assert!(matches!(
			observation.unwrap().entries(),
			[SyncPreviewEntry::Present(_), SyncPreviewEntry::Present(_)]
		)),
		Err(error) => {
			assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
			assert_system_cause(&observation.unwrap_err(), Errno::ACCESS);
		}
	}

	pair.recheck().unwrap();
	assert_eq!(fs::read(left).unwrap(), b"source");
	assert_eq!(fs::read(right_file).unwrap(), b"incumbent");
}

#[test]
fn typed_observation_refusals_explain_their_scope() {
	assert_diagnostic(&SyncPreviewError::AliasedFiles, "same file");
	assert_diagnostic(&SyncPreviewError::NameAlias, "differently spelled");
	assert_diagnostic(&SyncPreviewError::DirectoryLimit, "entry limit");
	assert_diagnostic(
		&SyncPreviewError::UnsupportedNamespace,
		"mount and user namespaces",
	);
	assert_diagnostic(
		&SyncPreviewError::UnsupportedHistoryNamePolicy,
		"exact unencrypted raw directory names",
	);
}
