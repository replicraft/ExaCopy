use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::windows::fs::OpenOptionsExt as _;

use windows_sys::Win32::Foundation::{ERROR_SHARING_VIOLATION, GENERIC_WRITE};
use windows_sys::Win32::Storage::FileSystem::{
	FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
};

use crate::windows::stage::tests::Fixture;

use super::super::{Binding, DIRECTORY_ACCESS, Directory, Kind, acl, named_identity, request};
use super::*;

#[test]
#[ignore = "requires a provisioned native local NTFS stage fixture"]
fn capture_sibling_refuses_substituted_busy_and_nonempty_native_records() {
	let fixture = Fixture::new();
	let outer = OpenOptions::new()
		.access_mode(DIRECTORY_ACCESS | FILE_ADD_SUBDIRECTORY)
		.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
		.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
		.open(&fixture.0)
		.unwrap();
	let subject = super::super::security::Subject::current().unwrap();
	let descriptor = super::super::CreationDescriptor::private_for_sid(&subject.sid).unwrap();
	let journal_units: Vec<_> = "journal".encode_utf16().collect();
	let journal_name = WindowsComponent::new(&journal_units).unwrap();
	let handle = descriptor
		.create(
			outer.as_handle(),
			journal_name,
			request(DIRECTORY_ACCESS | FILE_ADD_FILE),
			Kind::Directory,
		)
		.unwrap();
	let identity = named_identity(handle.as_handle(), Kind::Directory, journal_name).unwrap();
	let binding =
		Binding::capture(handle.as_handle(), identity, &subject, acl::Role::Private).unwrap();
	let directory = Directory { handle, binding };
	let name = WindowsComponent::new(&CAPTURE_NAME).unwrap();
	let path = fixture.0.join("journal").join("capture-v1.exajnl");
	let create = |name: WindowsComponent<'_>| {
		let file = descriptor
			.create(
				directory.handle.as_handle(),
				name,
				request(FILE_METADATA_ACCESS | FILE_READ_DATA | GENERIC_WRITE),
				Kind::RegularFile,
			)
			.unwrap();
		let identity = named_identity(file.as_handle(), Kind::RegularFile, name).unwrap();
		(File::from(file), identity)
	};
	let (provisioned, original) = create(name);
	drop(provisioned);
	let unrelated_units: Vec<_> = "unrelated".encode_utf16().collect();
	let unrelated_name = WindowsComponent::new(&unrelated_units).unwrap();
	let (unrelated, different) = create(unrelated_name);
	drop(unrelated);
	assert_ne!(original, different);
	assert!(matches!(
		open_empty_sibling(&directory, name, &subject, different),
		Err(Error::Changed)
	));

	let held = open_empty_sibling(&directory, name, &subject, original).unwrap();
	assert_eq!(held.pin.binding.identity, original);
	held.eof().unwrap();
	let competitor = OpenOptions::new()
		.read(true)
		.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
		.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
		.open(&path)
		.unwrap_err();
	assert_eq!(
		competitor.raw_os_error(),
		i32::try_from(ERROR_SHARING_VIOLATION).ok()
	);
	assert!(matches!(
		open_empty_sibling(&directory, name, &subject, original),
		Err(Error::Busy)
	));
	held.check(&directory, name).unwrap();
	drop(held);
	{
		let mut file = OpenOptions::new()
			.write(true)
			.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
			.open(&path)
			.unwrap();
		assert_eq!(
			named_identity(file.as_handle(), Kind::RegularFile, name).unwrap(),
			original
		);
		file.write_all(b"retained sibling").unwrap();
	}
	assert!(matches!(
		open_empty_sibling(&directory, name, &subject, original),
		Err(Error::Changed)
	));
	let retained = OpenOptions::new()
		.read(true)
		.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
		.open(&path)
		.unwrap();
	assert_eq!(
		named_identity(retained.as_handle(), Kind::RegularFile, name).unwrap(),
		original
	);
	assert_eq!(fs::read(&path).unwrap(), b"retained sibling");
	assert_eq!(
		fs::metadata(fixture.0.join("journal").join("unrelated"))
			.unwrap()
			.len(),
		0
	);
}
