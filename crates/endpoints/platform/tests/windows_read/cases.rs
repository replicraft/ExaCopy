use std::fs::{self, File, OpenOptions};
use std::os::windows::fs::{OpenOptionsExt, symlink_dir, symlink_file};
use std::os::windows::io::AsHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use exacopy_platform::windows::WindowsComponent;
use windows_sys::Win32::Foundation::{STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SHARING_VIOLATION};
use windows_sys::Win32::Storage::FileSystem::{
	FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
	FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
	FILE_WRITE_DATA, SYNCHRONIZE,
};

use crate::native::{HeldDirectory, ReadRefusal, Refusal};

pub(crate) struct Fixture(pub(crate) PathBuf);

impl Fixture {
	pub(crate) fn new() -> Self {
		let root = std::env::var_os("EXACOPY_WINDOWS_NTFS_ROOT")
			.expect("use the native Windows runner to provision a disposable NTFS root");
		Self::in_root(Path::new(&root))
	}

	pub(crate) fn in_root(root: &Path) -> Self {
		static NEXT_DIRECTORY: AtomicU32 = AtomicU32::new(0);
		const ATTEMPTS: u32 = 64;
		for _ in 0..ATTEMPTS {
			let attempt = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
			let path = root.join(format!(
				"exacopy-windows-read-{}-{attempt}",
				std::process::id()
			));
			match fs::create_dir(&path) {
				Ok(()) => return Self(path),
				Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
				Err(error) => panic!("could not create a synthetic fixture: {error}"),
			}
		}
		panic!("could not acquire an unused directory for a synthetic fixture");
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}

pub(crate) fn directory_handle(path: &Path, share_mode: u32) -> File {
	OpenOptions::new()
		.access_mode(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE)
		.share_mode(share_mode)
		.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
		.open(path)
		.expect("open a synthetic fixture directory")
}

fn units(name: &str) -> Vec<u16> {
	name.encode_utf16().collect()
}

fn component(units: &[u16]) -> WindowsComponent<'_> {
	WindowsComponent::new(units).expect("admit the synthetic fixture name")
}

#[test]
#[ignore = "requires the native fixed local NTFS fixture"]
fn ordinary_ntfs_opens_existing_child_by_component_and_reads_at_explicit_offsets() {
	let fixture = Fixture::new();
	fs::write(fixture.0.join("data"), b"abcdef").unwrap();
	fs::hard_link(fixture.0.join("data"), fixture.0.join("alias")).unwrap();
	fs::write(fixture.0.join("distinct"), b"abcdef").unwrap();
	let handle = directory_handle(&fixture.0, FILE_SHARE_READ);
	let root = HeldDirectory::inspect(handle.as_handle()).unwrap();
	let mut file = root.open(component(&units("data"))).unwrap();
	let alias = root.open(component(&units("alias"))).unwrap();
	let distinct = root.open(component(&units("distinct"))).unwrap();
	assert_eq!(file.identity(), alias.identity());
	assert_ne!(file.identity(), distinct.identity());
	let mut buffer = [0; 4];
	assert_eq!(file.read_at(4, &mut buffer).unwrap(), 2);
	assert_eq!(&buffer[..2], b"ef");
	assert_eq!(file.read_at(1, &mut buffer).unwrap(), 4);
	assert_eq!(&buffer, b"bcde");
	assert_eq!(file.read_at(6, &mut buffer).unwrap(), 0);
	assert!(matches!(
		file.read_at(i64::MAX as u64, &mut buffer),
		Err(ReadRefusal::InvalidRange)
	));
}

#[test]
#[ignore = "requires the native fixed local NTFS fixture"]
fn ordinary_ntfs_refuses_non_disk_and_existing_non_regular_child() {
	let fixture = Fixture::new();
	fs::create_dir(fixture.0.join("subdirectory")).unwrap();
	let (pipe, _writer) = std::io::pipe().unwrap();
	assert!(matches!(
		HeldDirectory::inspect(pipe.as_handle()),
		Err(Refusal::NotDisk)
	));
	let handle = directory_handle(&fixture.0, FILE_SHARE_READ);
	let root = HeldDirectory::inspect(handle.as_handle()).unwrap();
	assert!(root.open(component(&units("subdirectory"))).is_err());
	assert!(matches!(
		root.open(component(&units("absent"))),
		Err(Refusal::OpenFailed(STATUS_OBJECT_NAME_NOT_FOUND))
	));
	assert!(!fixture.0.join("absent").exists());
}

#[test]
#[ignore = "requires the native fixed local NTFS fixture"]
fn ordinary_ntfs_refuses_an_existing_writer_with_shared_read_access() {
	let fixture = Fixture::new();
	let data = fixture.0.join("data");
	fs::write(&data, b"fixture").unwrap();
	let _writer = OpenOptions::new()
		.access_mode(FILE_WRITE_DATA | SYNCHRONIZE)
		.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
		.open(&data)
		.unwrap();
	let handle = directory_handle(&fixture.0, FILE_SHARE_READ);
	let root = HeldDirectory::inspect(handle.as_handle()).unwrap();
	assert!(matches!(
		root.open(component(&units("data"))),
		Err(Refusal::OpenFailed(STATUS_SHARING_VIOLATION))
	));
}

#[test]
#[ignore = "requires the native fixed local NTFS fixture"]
fn ordinary_ntfs_resolves_against_held_directory_after_its_path_is_reused() {
	let fixture = Fixture::new();
	let original_path = fixture.0.join("original");
	let moved_path = fixture.0.join("moved");
	fs::create_dir(&original_path).unwrap();
	fs::write(original_path.join("data"), b"held").unwrap();
	let handle = directory_handle(&original_path, FILE_SHARE_READ | FILE_SHARE_DELETE);
	let root = HeldDirectory::inspect(handle.as_handle()).unwrap();
	fs::rename(&original_path, &moved_path).unwrap();
	fs::create_dir(&original_path).unwrap();
	fs::write(original_path.join("data"), b"decoy").unwrap();
	let mut file = root.open(component(&units("data"))).unwrap();
	let mut buffer = [0; 5];
	assert_eq!(file.read_at(0, &mut buffer).unwrap(), 4);
	assert_eq!(&buffer[..4], b"held");
}

#[test]
#[ignore = "run explicitly on local NTFS with Windows symlink fixture permission"]
fn refuses_reparse_leaf_and_parent() {
	let fixture = Fixture::new();
	fs::write(fixture.0.join("data"), b"target").unwrap();
	fs::create_dir(fixture.0.join("subdirectory")).unwrap();
	symlink_file(fixture.0.join("data"), fixture.0.join("file-link")).unwrap();
	symlink_dir(
		fixture.0.join("subdirectory"),
		fixture.0.join("directory-link"),
	)
	.unwrap();
	let parent = directory_handle(&fixture.0.join("directory-link"), FILE_SHARE_READ);
	assert!(matches!(
		HeldDirectory::inspect(parent.as_handle()),
		Err(Refusal::ReparsePoint)
	));
	let handle = directory_handle(&fixture.0, FILE_SHARE_READ);
	let mut root = HeldDirectory::inspect(handle.as_handle()).unwrap();
	assert!(matches!(
		root.open(component(&units("file-link"))),
		Err(Refusal::ReparsePoint)
	));
	assert!(matches!(
		root.open_by_id(component(&units("file-link"))),
		Err(crate::native::ByIdRefusal::WrongEntryKind)
	));
}

#[test]
#[ignore = "requires the native fixed local NTFS fixture"]
fn ordinary_ntfs_opens_an_exact_child_by_observed_ntfs_reference() {
	use crate::native::ByIdRefusal;

	let fixture = Fixture::new();
	fs::write(fixture.0.join("Exact"), b"held file").unwrap();
	fs::hard_link(fixture.0.join("Exact"), fixture.0.join("alias")).unwrap();
	fs::create_dir(fixture.0.join("directory")).unwrap();
	let handle = directory_handle(&fixture.0, FILE_SHARE_READ);
	let mut root = HeldDirectory::inspect(handle.as_handle()).unwrap();
	let mut file = root.open_by_id(component(&units("Exact"))).unwrap();
	let alias = root.open_by_id(component(&units("alias"))).unwrap();
	assert_eq!(file.identity(), alias.identity());
	let mut bytes = [0; 9];
	assert_eq!(file.read_at(0, &mut bytes).unwrap(), 9);
	assert_eq!(&bytes, b"held file");
	assert!(matches!(
		root.open_by_id(component(&units("EXACT"))),
		Err(ByIdRefusal::Missing)
	));
	assert!(matches!(
		root.open_by_id(component(&units("directory"))),
		Err(ByIdRefusal::WrongEntryKind)
	));
}

#[test]
#[ignore = "requires the native fixed local NTFS fixture"]
fn ordinary_ntfs_rejects_a_file_moved_out_of_the_held_parent_before_open_by_id() {
	use crate::native::ByIdRefusal;

	let fixture = Fixture::new();
	let original = fixture.0.join("original");
	fs::create_dir(&original).unwrap();
	let name = original.join("data");
	fs::write(&name, b"original data").unwrap();
	let handle = directory_handle(&original, FILE_SHARE_READ);
	let mut root = HeldDirectory::inspect(handle.as_handle()).unwrap();
	let outcome = root.open_by_id_after_observation(component(&units("data")), || {
		fs::rename(&name, fixture.0.join("moved")).unwrap();
		fs::write(&name, b"same-name replacement").unwrap();
	});
	assert!(matches!(outcome, Err(ByIdRefusal::EntryChanged)));
}
