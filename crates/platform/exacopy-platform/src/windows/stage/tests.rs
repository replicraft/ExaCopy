use std::fs::{self, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use windows_sys::Win32::Storage::FileSystem::{
	FILE_ADD_FILE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
	FILE_TRAVERSE,
};

use super::*;

pub(super) struct Fixture(pub(super) PathBuf);

impl Fixture {
	pub(super) fn new() -> Self {
		let root = std::env::var_os("EXACOPY_WINDOWS_NTFS_ROOT")
			.expect("provision a disposable owner-controlled local NTFS fixture root");
		static NEXT: AtomicU32 = AtomicU32::new(0);
		for _ in 0..64 {
			let attempt = NEXT.fetch_add(1, Ordering::Relaxed);
			let path =
				Path::new(&root).join(format!("exacopy-stage-{}-{attempt}", std::process::id()));
			match fs::create_dir(&path) {
				Ok(()) => return Self(path),
				Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
				Err(error) => panic!("cannot create fixture: {error}"),
			}
		}
		panic!("could not reserve unused test directory");
	}

	pub(super) fn open(&self) -> File {
		OpenOptions::new()
			.access_mode(
				FILE_ADD_FILE
					| FILE_LIST_DIRECTORY
					| FILE_TRAVERSE
					| FILE_READ_ATTRIBUTES
					| SYNCHRONIZE,
			)
			.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
			.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
			.open(&self.0)
			.unwrap()
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}

pub(super) fn component(units: &[u16]) -> WindowsComponent<'_> {
	WindowsComponent::new(units).unwrap()
}

#[test]
fn bounded_range_uses_the_model_guard_for_positive_lengths() {
	assert_eq!(range_end(1, 2, 3).unwrap(), 3);
	assert!(matches!(
		range_end(MAX_FILE_LENGTH, 1, MAX_FILE_LENGTH),
		Err(WindowsStageError::InvalidRange)
	));
	assert!(matches!(
		range_end(0, MAX_WINDOWS_STAGE_IO_BYTES + 1, MAX_FILE_LENGTH),
		Err(WindowsStageError::InvalidRange)
	));
	assert_eq!(range_end(3, 0, 3).unwrap(), 3);
	assert!(matches!(
		range_end(4, 0, 3),
		Err(WindowsStageError::InvalidRange)
	));
}

#[test]
#[ignore = "requires a provisioned native local NTFS stage fixture"]
fn bounded_writes_flush_close_and_reopen_the_original_file() {
	let fixture = Fixture::new();
	let parent = fixture.open();
	let root = WindowsStageDirectory::from_authorized_handle(parent.as_handle()).unwrap();
	let name: Vec<_> = "stage".encode_utf16().collect();
	let mut writer = root.create(component(&name), 6).unwrap();
	let identity = writer.identity();
	assert!(matches!(
		writer.write_at(1, b"x"),
		Err(WindowsStageError::InvalidRange)
	));
	assert!(matches!(
		writer.write_at(0, b""),
		Err(WindowsStageError::InvalidRange)
	));
	assert!(matches!(
		writer.write_at(0, b"too long"),
		Err(WindowsStageError::InvalidRange)
	));
	assert!(
		OpenOptions::new()
			.write(true)
			.open(fixture.0.join("stage"))
			.is_err()
	);

	writer.write_at(0, b"abc").unwrap();
	writer.write_at(3, b"def").unwrap();
	let mut reader = writer.finish().unwrap();
	assert_eq!(reader.identity(), identity);
	let mut read = [0; 4];
	reader.read_exact_at(2, &mut read).unwrap();
	assert_eq!(&read, b"cdef");
	assert!(matches!(
		reader.read_exact_at(3, &mut read),
		Err(WindowsStageError::InvalidRange)
	));
	reader.recheck().unwrap();
	drop(reader);
	assert_eq!(fs::read(fixture.0.join("stage")).unwrap(), b"abcdef");
}

#[test]
#[ignore = "requires a provisioned native local NTFS stage fixture"]
fn occupied_name_and_hard_link_preserve_original_bytes() {
	let fixture = Fixture::new();
	fs::write(fixture.0.join("incumbent"), b"original").unwrap();
	fs::hard_link(fixture.0.join("incumbent"), fixture.0.join("alias")).unwrap();
	let parent = fixture.open();
	let root = WindowsStageDirectory::from_authorized_handle(parent.as_handle()).unwrap();
	for requested in ["incumbent", "alias"] {
		let name: Vec<_> = requested.encode_utf16().collect();
		assert!(matches!(
			root.create(component(&name), 4),
			Err(WindowsStageError::Occupied)
		));
	}
	if fs::read(fixture.0.join("INCUMBENT")).as_deref().ok() == Some(b"original".as_slice()) {
		let case_alias: Vec<_> = "INCUMBENT".encode_utf16().collect();
		assert!(root.create(component(&case_alias), 4).is_err());
	}
	let unused: Vec<_> = "uncreated".encode_utf16().collect();
	assert!(matches!(
		root.create(component(&unused), u64::MAX),
		Err(WindowsStageError::InvalidExtent)
	));
	assert!(!fixture.0.join("uncreated").exists());
	assert_eq!(fs::read(fixture.0.join("incumbent")).unwrap(), b"original");
	assert_eq!(fs::read(fixture.0.join("alias")).unwrap(), b"original");
}

#[test]
#[ignore = "requires a provisioned native local NTFS stage fixture"]
fn incomplete_barrier_and_close_failures_retain_private_objects() {
	let fixture = Fixture::new();
	let parent = fixture.open();
	let root = WindowsStageDirectory::from_authorized_handle(parent.as_handle()).unwrap();
	for requested in ["incomplete", "barrier", "close"] {
		let name: Vec<_> = requested.encode_utf16().collect();
		let mut writer = root.create(component(&name), 6).unwrap();
		writer.write_at(0, b"abc").unwrap();
		if requested == "incomplete" {
			assert!(matches!(
				writer.finish(),
				Err(WindowsStageError::Incomplete)
			));
			assert_eq!(fs::read(fixture.0.join(requested)).unwrap(), b"abc");
			continue;
		}
		writer.write_at(3, b"def").unwrap();
		if requested == "barrier" {
			let outcome = writer.finish_with(
				|_| Err(io::Error::from_raw_os_error(29)),
				|_| panic!("failed barrier allowed successful writer retirement"),
			);
			assert!(matches!(outcome, Err(WindowsStageError::Barrier(_))));
		} else {
			let outcome = writer.finish_with(File::sync_all, |file| {
				close_writer(file)?;
				Err(io::Error::from_raw_os_error(6))
			});
			assert!(matches!(outcome, Err(WindowsStageError::CloseWriter(_))));
		}
		assert_eq!(fs::read(fixture.0.join(requested)).unwrap(), b"abcdef");
	}
}

#[test]
#[ignore = "requires a provisioned native local NTFS stage fixture"]
fn read_only_pin_blocks_rename_between_writer_close_and_reader_open() {
	let fixture = Fixture::new();
	let parent = fixture.open();
	let root = WindowsStageDirectory::from_authorized_handle(parent.as_handle()).unwrap();
	let name: Vec<_> = "stage".encode_utf16().collect();
	let writer = root.create(component(&name), 0).unwrap();
	let stage = fixture.0.join("stage");
	let replacement = fixture.0.join("replacement");
	let reader = writer
		.finish_with(File::sync_all, |file| {
			close_writer(file)?;
			assert!(fs::rename(&stage, &replacement).is_err());
			Ok(())
		})
		.unwrap();
	assert!(!replacement.exists());
	drop(reader);
	assert_eq!(fs::read(stage).unwrap(), b"");
}

#[test]
#[ignore = "requires a provisioned native local NTFS stage fixture"]
fn partial_write_failure_retires_the_writer_without_erasing_the_prefix() {
	let fixture = Fixture::new();
	let parent = fixture.open();
	let root = WindowsStageDirectory::from_authorized_handle(parent.as_handle()).unwrap();
	let name: Vec<_> = "stage".encode_utf16().collect();
	let mut writer = root.create(component(&name), 6).unwrap();
	let failed = writer.write_with(0, b"abcdef", |file, offset, bytes| {
		if offset == 0 {
			file.seek_write(&bytes[..1], 0)
		} else {
			Err(io::Error::from_raw_os_error(29))
		}
	});
	assert!(matches!(failed, Err(WindowsStageError::Write(_))));
	assert!(matches!(
		writer.write_at(0, b"abcdef"),
		Err(WindowsStageError::WriterRetired)
	));
	assert!(matches!(
		writer.finish(),
		Err(WindowsStageError::WriterRetired)
	));
	assert_eq!(fs::read(fixture.0.join("stage")).unwrap(), b"a");
}

#[test]
#[ignore = "requires native local NTFS and permission to create a file symbolic link"]
fn stage_symlink_preserves_existing_target() {
	let fixture = Fixture::new();
	let target = fixture.0.join("incumbent");
	fs::write(&target, b"preserve").unwrap();

	refuse_occupied_symlink(&fixture, &target);

	assert_eq!(fs::read(target).unwrap(), b"preserve");
}

#[test]
#[ignore = "requires native local NTFS and permission to create a file symbolic link"]
fn stage_symlink_does_not_create_a_dangling_target() {
	let fixture = Fixture::new();
	let target = fixture.0.join("absent");

	refuse_occupied_symlink(&fixture, &target);

	let error = fs::symlink_metadata(target).expect_err("the dangling referent must stay absent");
	assert_eq!(error.kind(), io::ErrorKind::NotFound);
}

fn refuse_occupied_symlink(fixture: &Fixture, target: &Path) {
	use std::os::windows::fs::symlink_file;

	let alias = fixture.0.join("alias");
	symlink_file(target, &alias).expect("the fixture needs Windows symlink permission");
	let original_link = fs::read_link(&alias).unwrap();
	let parent = fixture.open();
	let root = WindowsStageDirectory::from_authorized_handle(parent.as_handle()).unwrap();
	let name: Vec<_> = "alias".encode_utf16().collect();
	assert!(root.create(component(&name), 4).is_err());
	assert_eq!(fs::read_link(alias).unwrap(), original_link);
}
