use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::Path;

use exacopy_endpoint::UnixComponent;
use rustix::{fs as native_fs, process};

use super::{Error, FIRST_SEGMENT, PreparedActionSlotSelection};
use crate::linux::sync_profile_store::{SyncProfileStore, SyncProfileStoreError, mount_id, slot};
use crate::linux::{
	FileIdentity, ManagedSyncExpectedObject, ManagedSyncExpectedRoot, ManagedSyncNativeScope,
	SyncPreviewRoots,
};
use crate::scratch::Scratch;

const POLICY: &[u8] = b"independently selected fixture policy";
const PREPARED: &[u8] = b"fixture prepared bytes, not accepted storage history";
const SELECTION: [u8; 16] = [0x7a; 16];

#[test]
#[ignore = "requires an owned nonroot whole-ext4 managed fixture and cooperating actor"]
fn action_slot_holds_exclusion_and_refuses_same_byte_segment_rebinding() {
	let fixture = Scratch::new();
	let profile = fixture.path("profile");
	let history = fixture.path("history");
	let live = fixture.path("live");
	let action = profile.join("selected-action");
	let live_left = live.join("left");
	let live_right = live.join("right");
	let nested_history = action.join("nested-history");
	for directory in [
		&profile,
		&history,
		&live,
		&action,
		&live_left,
		&live_right,
		&nested_history,
	] {
		DirBuilder::new().mode(0o700).create(directory).unwrap();
	}
	let policy = profile.join(std::ffi::OsStr::from_bytes(&slot(SELECTION).unwrap()));
	let segment = action.join(FIRST_SEGMENT);
	write_new(&policy, POLICY);
	write_new(&segment, PREPARED);

	let children = [component(b"left"), component(b"right")];
	let roots = SyncPreviewRoots::open(&live, children).unwrap();
	let facts = roots.recheck_history_roots().unwrap();
	let [parent, _, _] = roots.held_directories();
	let ordinary_mount = NonZeroU64::new(mount_id(parent).unwrap()).unwrap();
	let scope = ManagedSyncNativeScope {
		parent_path: &live,
		uid: NonZeroU32::new(process::geteuid().as_raw()).unwrap(),
		gid: NonZeroU32::new(process::getegid().as_raw()).unwrap(),
		subject: component(b"subject"),
		boot: facts[0].boot,
		mount_namespace: expected(facts[0].mount_namespace),
		user_namespace: expected(facts[0].user_namespace),
		ordinary_mount,
		unique_mount: facts[0].unique_mount,
		parent: expected(facts[0].parent),
		roots: facts.map(|fact| ManagedSyncExpectedRoot {
			name: fact.root_name,
			identity: expected(fact.root),
		}),
	};
	let policy_store = SyncProfileStore::open(&profile).unwrap();
	let policy_record = policy_store.read(SELECTION).unwrap();
	let selected_history = policy_record.open_history(&history).unwrap();
	let pair = roots.acquire_managed_preparation_lease(scope).unwrap();
	let segment_identity = identity(&segment);
	let select = PreparedActionSlotSelection {
		name: component(b"selected-action"),
		directory: expected(identity(&action)),
		segment: expected(segment_identity),
		ordinary_mount,
		unique_mount: facts[0].unique_mount,
		extent: NonZeroUsize::new(PREPARED.len()).unwrap(),
		limit: NonZeroUsize::new(256).unwrap(),
	};
	for history_path in [&nested_history, &live] {
		let overlapping = policy_record.open_history(history_path).unwrap();
		assert!(matches!(
			policy_record.open_selected_action_slot(&overlapping, &pair, select),
			Err(Error::Scope(SyncProfileStoreError::OverlappingRoles)),
		));
	}
	assert!(matches!(
		policy_record.open_selected_action_slot(
			&selected_history,
			&pair,
			PreparedActionSlotSelection {
				extent: NonZeroUsize::new(257).unwrap(),
				..select
			}
		),
		Err(Error::Bounds),
	));
	assert!(matches!(
		policy_record.open_selected_action_slot(
			&selected_history,
			&pair,
			PreparedActionSlotSelection {
				extent: NonZeroUsize::new(PREPARED.len() + 1).unwrap(),
				..select
			}
		),
		Err(Error::Segment(SyncProfileStoreError::InvalidExtent)),
	));
	let held = policy_record
		.open_selected_action_slot(&selected_history, &pair, select)
		.unwrap();
	assert!(matches!(
		policy_record.open_selected_action_slot(&selected_history, &pair, select),
		Err(Error::Directory(SyncProfileStoreError::Busy)),
	));
	let mut bytes = [0; PREPARED.len()];
	held.read_prepared(&mut bytes).unwrap();
	assert_eq!(&bytes, PREPARED);
	assert!(matches!(held.read_prepared(&mut []), Err(Error::Bounds)));

	// The fixture deliberately rebinds its own slot to challenge current custody.
	let retained = action.join("retained-original");
	fs::rename(&segment, &retained).unwrap();
	write_new(&segment, PREPARED);
	let mut sentinel = [0x39; PREPARED.len()];
	assert!(matches!(
		held.read_prepared(&mut sentinel),
		Err(Error::Segment(SyncProfileStoreError::Changed)),
	));
	assert_eq!(sentinel, [0x39; PREPARED.len()]);
	drop(held);
	assert!(matches!(
		policy_record.open_selected_action_slot(&selected_history, &pair, select),
		Err(Error::Segment(SyncProfileStoreError::Changed)),
	));
	assert_eq!(identity(&retained), segment_identity);
	assert_ne!(identity(&segment), segment_identity);
	assert_eq!(fs::read(retained).unwrap(), PREPARED);
	assert_eq!(fs::read(segment).unwrap(), PREPARED);
	assert_eq!(fs::read(policy).unwrap(), POLICY);
	assert_eq!(
		fs::symlink_metadata(action.join("activation.claim"))
			.unwrap_err()
			.kind(),
		ErrorKind::NotFound
	);
}

fn component(raw: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(raw).unwrap()
}

fn expected(identity: FileIdentity) -> ManagedSyncExpectedObject {
	ManagedSyncExpectedObject {
		major: native_fs::major(identity.device()),
		minor: native_fs::minor(identity.device()),
		inode: NonZeroU64::new(identity.inode()).unwrap(),
	}
}

fn identity(path: &Path) -> FileIdentity {
	FileIdentity::from_stat(
		&native_fs::statat(native_fs::CWD, path, native_fs::AtFlags::SYMLINK_NOFOLLOW).unwrap(),
	)
}

fn write_new(path: &Path, bytes: &[u8]) {
	OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(path)
		.unwrap()
		.write_all(bytes)
		.unwrap();
}
