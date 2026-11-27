use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _, symlink};
use std::path::Path;

use exacopy_endpoint::UnixComponent;

use super::{SyncProfileStore, SyncProfileStoreError, check_extent, mount_id, pin::Pin, slot};
use crate::linux::{OWNER_SEED_BYTES, SyncPreviewRoots};
use crate::scratch::Scratch;

const ID: [u8; 16] = [0xab; 16];
const RECORD: &[u8] = b"exact synthetic policy record";

#[test]
fn fixed_selection_derives_one_canonical_nonzero_slot_and_extent() {
	assert_eq!(
		slot(ID).unwrap(),
		b"managed-sync-abababababababababababababababab.v1"
	);
	assert!(matches!(
		slot([0; 16]),
		Err(SyncProfileStoreError::InvalidSelection)
	));
	assert!(check_extent(24 * 1024).is_ok());
	for size in [0, 24 * 1024 + 1, usize::MAX] {
		assert!(matches!(
			check_extent(size),
			Err(SyncProfileStoreError::InvalidExtent)
		));
	}
}

#[test]
fn held_regular_pin_reads_private_bytes() {
	let scratch = Scratch::new();
	private_file(&scratch.path("private-record"), RECORD);
	let parent = scratch.open();
	let owner = rustix::process::geteuid().as_raw();
	let pin = Pin::open(
		&parent,
		b"private-record",
		owner,
		mount_id(&parent).unwrap(),
	)
	.unwrap();
	let mut record = [0; RECORD.len()];
	pin.read(&parent, &mut record, &mut [0]).unwrap();
	assert_eq!(record.as_slice(), RECORD);
}

#[test]
#[ignore = "requires a protected nonroot whole ext4 TMPDIR and cooperating fixture owner"]
fn preview_does_not_open_seed_and_rechecks_an_exact_held_record() {
	let scratch = Scratch::new();
	let profile = scratch.path("profile");
	private_directory(&profile);
	let record = profile.join(std::ffi::OsStr::from_bytes(&slot(ID).unwrap()));
	private_file(&record, RECORD);
	symlink("absent.seed", profile.join("owner.seed")).unwrap();

	let held = SyncProfileStore::open(&profile).unwrap();
	let selected = held.read(ID).unwrap();
	assert_eq!(selected.bytes(), RECORD);
	selected.recheck().unwrap();

	fs::rename(&record, profile.join("retained-record")).unwrap();
	private_file(&record, RECORD);
	assert!(selected.recheck().is_err());
	assert_eq!(fs::read(profile.join("retained-record")).unwrap(), RECORD);
	assert_eq!(fs::read(&record).unwrap(), RECORD);
}

#[test]
#[ignore = "requires a protected nonroot whole ext4 TMPDIR and cooperating fixture owner"]
fn init_rechecks_seed_and_withdraws_no_incumbent_or_existing_bytes() {
	let scratch = Scratch::new();
	let profile = scratch.path("profile");
	private_directory(&profile);
	let seed_path = profile.join("owner.seed");
	private_file(&seed_path, &[3; OWNER_SEED_BYTES]);
	let store = SyncProfileStore::open(&profile).unwrap();
	let mut seed = [0; OWNER_SEED_BYTES];
	let mut check = [0; OWNER_SEED_BYTES];
	let mut eof = [0];
	let admission = store.open_seed(&mut seed, &mut eof).unwrap();
	let selected = admission
		.create(ID, RECORD, &seed, &mut check, &mut eof)
		.unwrap();
	assert!(matches!(store.read(ID), Err(SyncProfileStoreError::Busy)));
	assert_eq!(selected.bytes(), RECORD);
	selected.recheck().unwrap();
	drop(selected);

	let admission = store.open_seed(&mut seed, &mut eof).unwrap();
	assert!(matches!(
		admission.create(ID, b"incumbent must survive", &seed, &mut check, &mut eof),
		Err(SyncProfileStoreError::AlreadyExists)
	));
	let selected = store.read(ID).unwrap();
	assert_eq!(selected.bytes(), RECORD);
	drop(selected);

	let admission = store.open_seed(&mut seed, &mut eof).unwrap();
	fs::write(&seed_path, [4; OWNER_SEED_BYTES]).unwrap();
	assert!(
		admission
			.create([0xbc; 16], RECORD, &seed, &mut check, &mut eof)
			.is_err()
	);
	let absent = slot([0xbc; 16]).unwrap();
	assert!(!profile.join(std::ffi::OsStr::from_bytes(&absent)).exists());
}

#[test]
#[ignore = "requires a protected nonroot whole ext4 TMPDIR and cooperating fixture owner"]
fn profile_history_and_live_roots_may_share_an_ancestor_but_never_overlap() {
	let scratch = Scratch::new();
	let common = scratch.path("common");
	private_directory(&common);
	for child in ["profile", "history", "left", "right"] {
		private_directory(&common.join(child));
	}
	private_directory(&common.join("left/nested"));
	let store = SyncProfileStore::open(&common.join("profile")).unwrap();
	let roots = SyncPreviewRoots::open(
		&common,
		[
			UnixComponent::new(b"left").unwrap(),
			UnixComponent::new(b"right").unwrap(),
		],
	)
	.unwrap();
	let history = store.open_history(&common.join("history")).unwrap();
	store.check_disjoint(&history, &roots).unwrap();
	for conflict in ["left", "left/nested", "profile"] {
		let history = store.open_history(&common.join(conflict)).unwrap();
		assert!(matches!(
			store.check_disjoint(&history, &roots),
			Err(SyncProfileStoreError::OverlappingRoles)
		));
	}
	fs::rename(common.join("history"), common.join("retained")).unwrap();
	private_directory(&common.join("history"));
	assert!(store.check_disjoint(&history, &roots).is_err());
}

fn private_directory(path: &Path) {
	fs::DirBuilder::new().mode(0o700).create(path).unwrap();
	fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn private_file(path: &Path, bytes: &[u8]) {
	use std::io::Write as _;

	let mut file = fs::OpenOptions::new()
		.create_new(true)
		.write(true)
		.mode(0o600)
		.open(path)
		.unwrap();
	file.write_all(bytes).unwrap();
}
