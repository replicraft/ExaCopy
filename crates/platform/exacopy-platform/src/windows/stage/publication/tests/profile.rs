use std::mem::size_of;
use std::os::windows::fs::symlink_dir;
use std::os::windows::io::AsRawHandle as _;

use windows_sys::Win32::Storage::FileSystem::{
	FILE_ATTRIBUTE_NORMAL, FILE_BASIC_INFO, FileBasicInfo, SetFileInformationByHandle,
};

use super::*;

pub(super) fn refuse_existing_destination_after_removed_predecessor() {
	let fixture = Fixture::new();
	fs::create_dir(&fixture.destination).unwrap();
	let predecessor = fixture.destination.join("public");
	create_bytes(&predecessor, b"recently removed destination predecessor");
	fs::remove_file(&predecessor).unwrap();
	assert_absent(&predecessor);
	let root_file = open_parent(&fixture.scope, FILE_ADD_SUBDIRECTORY);
	let root = WindowsPublicationRoot::from_authorized_handle(root_file.as_handle()).unwrap();
	let existing = open_parent(&fixture.destination, 0);
	let identity = observe(existing.as_handle(), Kind::Directory).unwrap();
	assert!(matches!(
		root.create_destination(WindowsComponent::new(DESTINATION).unwrap()),
		Err(WindowsPublicationError::DestinationOccupied)
	));
	assert_eq!(
		observe(existing.as_handle(), Kind::Directory).unwrap(),
		identity
	);
	assert_absent(&predecessor);
	drop(existing);
	drop(root_file);
	fixture.clean([]);
}

pub(super) fn refuse_reparse_destination() {
	let fixture = Fixture::new();
	symlink_dir(&fixture.stage, &fixture.destination)
		.expect("the hosted reparse oracle requires the synthetic directory-link capability");
	let original_link = fs::read_link(&fixture.destination).unwrap();
	let root_file = open_parent(&fixture.scope, FILE_ADD_SUBDIRECTORY);
	let root = WindowsPublicationRoot::from_authorized_handle(root_file.as_handle()).unwrap();
	let stage_file = open_parent(&fixture.stage, 0);
	let stage = observe(stage_file.as_handle(), Kind::Directory).unwrap();
	let outcome = root.create_destination(WindowsComponent::new(DESTINATION).unwrap());
	assert!(matches!(
		outcome,
		Err(WindowsPublicationError::DestinationOccupied
			| WindowsPublicationError::DestinationCreateUncertain(_))
	));
	assert_eq!(fs::read_link(&fixture.destination).unwrap(), original_link);
	assert_eq!(
		observe(stage_file.as_handle(), Kind::Directory).unwrap(),
		stage
	);
	assert_eq!(fs::read_dir(&fixture.stage).unwrap().count(), 0);
	fs::remove_dir(&fixture.destination).unwrap();
	assert_absent(&fixture.destination);
	assert_eq!(
		observe(stage_file.as_handle(), Kind::Directory).unwrap(),
		stage
	);
	drop(stage_file);
	drop(root_file);
	fs::remove_dir(fixture.stage).unwrap();
	fs::remove_dir(fixture.scope).unwrap();
}

#[allow(
	unsafe_code,
	reason = "controlled write of initial attributes on one synthetic stage"
)]
fn clear_archive(file: &File) {
	let mut metadata = FILE_BASIC_INFO {
		FileAttributes: FILE_ATTRIBUTE_NORMAL,
		..Default::default()
	};
	let size = u32::try_from(size_of::<FILE_BASIC_INFO>()).unwrap();
	// SAFETY: This held synthetic file permits WRITE_ATTRIBUTES. The initialized
	// metadata input and its size match FileBasicInfo and remain live during the call.
	let success = unsafe {
		SetFileInformationByHandle(
			file.as_raw_handle(),
			FileBasicInfo,
			(&raw mut metadata).cast(),
			size,
		)
	};
	assert_ne!(success, 0, "{}", io::Error::last_os_error());
}

pub(super) fn refuse_initial_archive_transition() {
	let fixture = Fixture::new();
	let private = fixture.stage.join("stage");
	let public = fixture.destination.join("public");
	let stage_file = open_parent(&fixture.stage, FILE_ADD_FILE);
	let root_file = open_parent(&fixture.scope, FILE_ADD_SUBDIRECTORY);
	let root = WindowsPublicationRoot::from_authorized_handle(root_file.as_handle()).unwrap();
	let destination = root
		.create_destination(WindowsComponent::new(DESTINATION).unwrap())
		.unwrap();
	let stage = WindowsStageDirectory::from_authorized_handle(stage_file.as_handle()).unwrap();
	let writer = new_writer(&stage);
	let identity = writer.identity();
	writer.file.as_ref().unwrap().sync_all().unwrap();
	let attributes = OpenOptions::new()
		.access_mode(FILE_WRITE_ATTRIBUTES)
		.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
		.open(&private)
		.unwrap();
	clear_archive(&attributes);
	drop(attributes);
	let closed = close_for_target(writer, destination);
	assert_eq!(
		fs::metadata(&private).unwrap().file_attributes(),
		FILE_ATTRIBUTE_NORMAL
	);
	assert!(matches!(
		closed.observe_metadata(),
		Err(WindowsPublicationError::UnsupportedMetadata)
	));
	assert_bytes(&private, identity, DATA);
	assert_absent(&public);
	drop(closed);
	drop(stage_file);
	drop(root_file);
	fixture.clean([(private, identity)]);
}
