use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle};
use std::path::{Path, PathBuf, Prefix};

use exacopy_platform::windows::WindowsComponent;
use windows_sys::Win32::Storage::FileSystem::{
	FILE_ATTRIBUTE_TAG_INFO, FILE_ID_INFO, FILE_NAME_OPENED, FILE_READ_ATTRIBUTES,
	FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileAttributeTagInfo, FileIdInfo,
	GetFinalPathNameByHandleW, VOLUME_NAME_GUID,
};
use windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_MOUNT_POINT;

use super::{ByIdRefusal, HeldDirectory, ReadMode, Refusal, lookup};
use crate::cases::{Fixture, directory_handle};
use crate::directory_entries::DirectoryEntry;
use crate::native::{POSITIONED_READ_CALLS, query};

#[path = "qualification/junction.rs"]
mod junction;
use junction::{Junction, junction_mutator};

const PROBE: &str = "probe.dat";

fn component(units: &[u16]) -> WindowsComponent<'_> {
	WindowsComponent::new(units).expect("admit the test's counted UTF-16 component")
}

fn handle_id(handle: BorrowedHandle<'_>) -> (u64, [u8; 16]) {
	let mut info = FILE_ID_INFO::default();
	// SAFETY: FileIdInfo expects an initialized FILE_ID_INFO output.
	unsafe { query(handle, FileIdInfo, &mut info) }.expect("query independent fixture file ID");
	(info.VolumeSerialNumber, info.FileId.Identifier)
}

fn follow_id(path: &Path) -> (u64, [u8; 16]) {
	let handle = OpenOptions::new()
		.access_mode(FILE_READ_ATTRIBUTES)
		.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
		.open(path)
		.expect("open the explicit pathname control with metadata-only access");
	handle_id(handle.as_handle())
}

fn assert_rejected(
	outcome: Result<impl Sized, ByIdRefusal>,
	expected: impl FnOnce(ByIdRefusal) -> bool,
	before: u32,
) {
	let Err(error) = outcome else {
		panic!("rejected name exposed a candidate read capability");
	};
	eprintln!("candidate refusal: {error:?}");
	assert!(expected(error), "candidate returned an unexpected refusal");
	assert_eq!(
		POSITIONED_READ_CALLS.get(),
		before,
		"rejected name issued a candidate read"
	);
}

fn guid_spelling(handle: BorrowedHandle<'_>) -> io::Result<PathBuf> {
	let mut path = vec![0_u16; 32_768];
	// SAFETY: The handle stays live and the buffer has the specified count of UTF-16 units.
	let count = unsafe {
		GetFinalPathNameByHandleW(
			handle.as_raw_handle(),
			path.as_mut_ptr(),
			u32::try_from(path.len()).expect("bounded Win32 buffer"),
			VOLUME_NAME_GUID | FILE_NAME_OPENED,
		)
	};
	if count == 0 {
		return Err(io::Error::last_os_error());
	}
	let count = usize::try_from(count).expect("u32 count fits in usize");
	assert!(
		count < path.len(),
		"exact GUID pathname must fit in the fixture buffer"
	);
	Ok(OsString::from_wide(&path[..count]).into())
}

#[test]
#[ignore = "requires the native fixed local NTFS fixture"]
fn ordinary_ntfs_native_id_and_guid_match_the_independent_path_oracle() {
	let fixture = Fixture::new();
	let file_path = fixture.0.join(PROBE);
	fs::write(&file_path, b"id oracle").expect("create independent file contents");
	let expected = follow_id(&file_path);
	let parent = directory_handle(&fixture.0, FILE_SHARE_READ);
	let guid_path = guid_spelling(parent.as_handle()).expect("resolve local NTFS volume GUID");
	let guid_units: Vec<_> = guid_path.as_os_str().encode_wide().collect();
	let guid_prefix: Vec<_> = r"\\?\Volume{".encode_utf16().collect();
	assert!(guid_units.starts_with(&guid_prefix), "{guid_path:?}");
	let guid_parent = directory_handle(&guid_path, FILE_SHARE_READ);
	assert_eq!(
		handle_id(parent.as_handle()),
		handle_id(guid_parent.as_handle()),
		"GUID alias changed parent identity"
	);
	assert_eq!(
		follow_id(&guid_path.join(PROBE)),
		expected,
		"GUID alias changed the pathname oracle"
	);

	let name: Vec<_> = PROBE.encode_utf16().collect();
	let observed =
		lookup(parent.as_handle(), component(&name)).expect("enumerate native 128-bit reference");
	assert_eq!(
		observed.id, expected.1,
		"native enumeration and FileIdInfo must agree"
	);
	let mut held = HeldDirectory::inspect(parent.as_handle()).expect("admit local NTFS parent");
	let mut held_guid =
		HeldDirectory::inspect(guid_parent.as_handle()).expect("admit same GUID parent");
	let mut file = held
		.open_by_id(component(&name))
		.expect("native ExtendedFileIdType open on NTFS");
	let alias = held_guid
		.open_by_id(component(&name))
		.expect("native ExtendedFileIdType open with GUID parent");
	assert_eq!(
		file.identity(),
		alias.identity(),
		"two native opens must agree on object identity"
	);
	assert_eq!(
		handle_id(file.file.as_handle()),
		expected,
		"opened handle must have exact serial and ID"
	);
	eprintln!(
		"GUID and 128-bit reference: {:?}, {expected:02x?}",
		file.identity()
	);
	let before = POSITIONED_READ_CALLS.get();
	let mut bytes = [0; 6];
	assert_eq!(
		file.read_at(3, &mut bytes).expect("positioned read"),
		bytes.len()
	);
	assert_eq!(
		&bytes, b"oracle",
		"positive read must come from the held object"
	);
	assert_eq!(
		POSITIONED_READ_CALLS.get(),
		before + 1,
		"positive control for read counter"
	);
}

#[test]
#[ignore = "requires the native fixed local NTFS fixture"]
fn ordinary_ntfs_native_case_and_surrogate_units_are_preserved() {
	let fixture = Fixture::new();
	let cases = [[0x005a, 0xd800], [0x005a, 0xfffd], [0x005a, 0xdc00]];
	for (index, name) in cases.iter().enumerate() {
		let path = fixture.0.join(OsString::from_wide(name));
		fs::write(&path, [u8::try_from(index).expect("test name index")])
			.unwrap_or_else(|error| panic!("create native counted name {name:04x?}: {error}"));
	}
	let parent = directory_handle(&fixture.0, FILE_SHARE_READ);
	let mut held = HeldDirectory::inspect(parent.as_handle()).expect("admit fixture parent");
	let mut file_ids = Vec::new();
	for (index, name) in cases.iter().enumerate() {
		let expected = follow_id(&fixture.0.join(OsString::from_wide(name)));
		assert!(
			!file_ids.contains(&expected),
			"distinct UTF-16 names must have distinct IDs"
		);
		file_ids.push(expected);
		let mut file = held
			.open_by_id(component(name))
			.unwrap_or_else(|error| panic!("open counted name {name:04x?}: {error}"));
		assert_eq!(
			handle_id(file.file.as_handle()),
			expected,
			"counted name {name:04x?}"
		);
		let mut value = [255];
		assert_eq!(file.read_at(0, &mut value).expect("read selected name"), 1);
		assert_eq!(
			usize::from(value[0]),
			index,
			"selected file for {name:04x?}"
		);
	}
	let before = POSITIONED_READ_CALLS.get();
	assert_rejected(
		held.open_by_id(component(&[0x007a, 0xd800])),
		|error| matches!(error, ByIdRefusal::Missing),
		before,
	);
}

#[test]
#[ignore = "requires the native fixed local NTFS fixture"]
fn ordinary_ntfs_native_renamed_parent_keeps_identity_when_old_path_becomes_junction() {
	let fixture = Fixture::new();
	let original = fixture.0.join("original");
	let moved = fixture.0.join("moved");
	let decoy = fixture.0.join("decoy");
	for path in [&original, &decoy] {
		fs::create_dir(path).expect("create synthetic directory");
	}
	fs::write(original.join(PROBE), b"held").expect("write direct child");
	fs::write(decoy.join(PROBE), b"redirect").expect("write decoy child");
	let original_id = follow_id(&original.join(PROBE));
	let parent = directory_handle(&original, FILE_SHARE_READ | FILE_SHARE_DELETE);
	let mut held = HeldDirectory::inspect(parent.as_handle()).expect("admit original parent");
	// Keep the checked handle across the rename, but mutate the newly created old name.
	fs::rename(&original, &moved).expect("rename the held directory");
	fs::create_dir(&original).expect("reuse the old spelling for the junction");
	let mutator = junction_mutator(&original);
	let tag = Junction::set(mutator.as_handle(), &decoy);
	assert_eq!(
		follow_id(&original.join(PROBE)),
		follow_id(&decoy.join(PROBE)),
		"following the old spelling must reach the decoy"
	);
	let reopened = directory_handle(&original, FILE_SHARE_READ);
	let before = POSITIONED_READ_CALLS.get();
	assert!(
		matches!(
			HeldDirectory::inspect(reopened.as_handle()),
			Err(Refusal::ReparsePoint)
		),
		"a newly opened junction must be refused"
	);
	assert_eq!(
		POSITIONED_READ_CALLS.get(),
		before,
		"refusal should not read the decoy"
	);
	let name: Vec<_> = PROBE.encode_utf16().collect();
	let selected = held
		.open_by_id(component(&name))
		.expect("held parent remains direct after rename");
	assert_eq!(
		handle_id(selected.file.as_handle()),
		original_id,
		"held selection must retain the original ID"
	);
	assert_ne!(
		original_id,
		follow_id(&decoy.join(PROBE)),
		"distinct synthetic decoy"
	);
	tag.clear();
}

fn tag_of(handle: BorrowedHandle<'_>) -> u32 {
	let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
	// SAFETY: FileAttributeTagInfo expects an initialized FILE_ATTRIBUTE_TAG_INFO output.
	unsafe { query(handle, FileAttributeTagInfo, &mut info) }.expect("query held parent tag");
	info.ReparseTag
}

fn lookup_while_tagged(
	parent: BorrowedHandle<'_>,
	mutator: &File,
	original: &Path,
	decoy: &Path,
	name: WindowsComponent<'_>,
) -> Result<DirectoryEntry, ByIdRefusal> {
	let original_id = handle_id(parent);
	let decoy_id = follow_id(&decoy.join(PROBE));
	let tag = Junction::set(mutator.as_handle(), decoy);
	assert_eq!(
		tag_of(parent),
		IO_REPARSE_TAG_MOUNT_POINT,
		"held handle must observe the tag"
	);
	assert_eq!(
		follow_id(&original.join(PROBE)),
		decoy_id,
		"positive follow oracle"
	);
	let result = lookup(parent, name);
	eprintln!(
		"held tagged-parent lookup: {result:?}, original={original_id:02x?}, decoy={decoy_id:02x?}"
	);
	tag.clear();
	assert_eq!(
		tag_of(parent),
		0,
		"tag should be removed before the outer check"
	);
	assert_eq!(
		handle_id(parent),
		original_id,
		"tag mutation must preserve parent identity"
	);
	assert!(
		!original.join(PROBE).exists(),
		"the original parent must remain empty"
	);
	assert!(
		matches!(
			result,
			Err(ByIdRefusal::Missing | ByIdRefusal::DirectoryQuery(_))
		),
		"raw enumeration exposed a record or invalid evidence from an empty parent: {result:?}"
	);
	result
}

fn tagged_parent_cases(fixture: &Fixture, decoy_root: &Path, expect_cross_volume: bool) {
	let original = fixture.0.join("parent");
	let decoy = decoy_root.join("target");
	fs::create_dir(&original).expect("create empty held parent");
	fs::create_dir(&decoy).expect("create synthetic junction target");
	fs::write(decoy.join(PROBE), b"redirect").expect("write decoy child");
	let parent = directory_handle(&original, FILE_SHARE_READ);
	let mutator = junction_mutator(&original);
	let mut held = HeldDirectory::inspect(parent.as_handle()).expect("admit plain held parent");
	let decoy_directory = directory_handle(&decoy, FILE_SHARE_READ);
	let decoy_volume = HeldDirectory::inspect(decoy_directory.as_handle())
		.expect("independently admit the junction target as a local NTFS directory");
	assert_eq!(
		held.identity.volume != decoy_volume.identity.volume,
		expect_cross_volume,
		"verify requested volume separation by GUID"
	);
	eprintln!("junction parent identity: {:?}", held.identity);
	eprintln!("junction target identity: {:?}", decoy_volume.identity);
	let name: Vec<_> = PROBE.encode_utf16().collect();
	let before = POSITIONED_READ_CALLS.get();
	let tag = Junction::set(mutator.as_handle(), &decoy);
	assert_eq!(
		follow_id(&original.join(PROBE)),
		follow_id(&decoy.join(PROBE)),
		"steady-tag follow control"
	);
	assert_rejected(
		held.open_by_id(component(&name)),
		|error| matches!(error, ByIdRefusal::Native(Refusal::ReparsePoint)),
		before,
	);
	tag.clear();

	let outcome = held.open_by_id_with_observations(
		component(&name),
		ReadMode::Synchronous,
		|directory, name| lookup_while_tagged(directory, &mutator, &original, &decoy, name),
		|| panic!("the first tagged scan must refuse before the by-ID open"),
	);
	assert_rejected(
		outcome,
		|error| matches!(error, ByIdRefusal::Missing | ByIdRefusal::DirectoryQuery(_)),
		before,
	);

	let source = original.join(PROBE);
	let moved = fixture.0.join("moved.dat");
	fs::write(&source, b"original").expect("create a direct file for the second observation");
	let expected = follow_id(&source);
	let mut observations = 0;
	let outcome = held.open_by_id_with_observations(
		component(&name),
		ReadMode::Synchronous,
		|directory, name| {
			observations += 1;
			if observations == 1 {
				let entry = lookup(directory, name).expect("positive untagged direct-child scan");
				assert_eq!(entry.id, expected.1, "same file before the rename");
				return Ok(entry);
			}
			lookup_while_tagged(directory, &mutator, &original, &decoy, name)
		},
		|| {
			fs::rename(&source, &moved)
				.expect("move original outside the held parent before by-ID open");
			assert_eq!(
				follow_id(&moved),
				expected,
				"moved object keeps the initial file ID"
			);
		},
	);
	assert_eq!(
		observations, 2,
		"reach the tagged membership recheck after the by-ID open"
	);
	assert_rejected(
		outcome,
		|error| matches!(error, ByIdRefusal::Missing | ByIdRefusal::DirectoryQuery(_)),
		before,
	);
}

#[test]
#[ignore = "requires the native fixed local NTFS fixture"]
fn ordinary_ntfs_native_held_parent_refuses_junction_during_each_raw_observation() {
	let fixture = Fixture::new();
	tagged_parent_cases(&fixture, &fixture.0, false);
}

#[test]
#[ignore = "requires a second explicitly provisioned local NTFS volume"]
fn native_cross_volume_held_parent_junction_is_refused() {
	let other = std::env::var_os("EXACOPY_WINDOWS_SECOND_NTFS_ROOT")
		.expect("provide a disposable local root on a second NTFS volume");
	let fixture = Fixture::new();
	let target = Fixture::in_root(Path::new(&other));
	tagged_parent_cases(&fixture, &target.0, true);
}

#[test]
#[ignore = "requires an explicitly provisioned writable disposable SMB fixture share"]
fn native_unc_handle_has_no_local_volume_guid_and_is_refused() {
	let root = std::env::var_os("EXACOPY_WINDOWS_UNC_ROOT")
		.expect("provide an existing disposable SMB share root");
	let root = Path::new(&root);
	assert!(
		matches!(root.components().next(), Some(std::path::Component::Prefix(prefix))
		if matches!(prefix.kind(), Prefix::UNC(..) | Prefix::VerbatimUNC(..))),
		"use an explicit UNC path"
	);
	let fixture = Fixture::in_root(root);
	fs::write(fixture.0.join(PROBE), b"remote fixture").expect("create positive UNC control");
	let handle = directory_handle(&fixture.0, FILE_SHARE_READ);
	let raw_guid = guid_spelling(handle.as_handle())
		.expect_err("SMB handle must not have a Mount Manager volume GUID");
	let outcome = HeldDirectory::inspect(handle.as_handle());
	eprintln!(
		"UNC GUID query: {raw_guid:?}, inspect refusal: {:?}",
		outcome.as_ref().err()
	);
	assert!(
		matches!(
			outcome,
			Err(Refusal::QueryFailed(_) | Refusal::NotNtfs | Refusal::UnidentifiedVolume)
		),
		"UNC must be refused during parent admission"
	);
	assert_eq!(
		POSITIONED_READ_CALLS.get(),
		0,
		"UNC admission must issue no candidate reads"
	);
}
