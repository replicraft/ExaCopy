use std::fs::{self, File};
use std::os::fd::AsFd;
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;

use crate::scratch::Scratch;

use super::*;

const SELECTED: &str = "selected";
const OTHER: &str = "other";

fn slot<'parent>(parent: &'parent File, name: &'static str) -> HeldSlot<'parent> {
	HeldSlot::from_authorized_parent(
		parent.as_fd(),
		UnixComponent::new(name.as_bytes()).expect("synthetic component is valid"),
	)
	.expect("admit synthetic held parent")
}

fn present<'slot, 'scope>(slot: &'slot HeldSlot<'scope>) -> PinnedEntry<'slot, 'scope> {
	let SlotObservation::Present(entry) = slot.observe().expect("observe fixture") else {
		panic!("fixture should have an occupant");
	};
	entry
}

#[test]
fn distinguishes_lookup_absence_and_rebound_objects() {
	let fixture = Scratch::new();
	let parent = fixture.open();
	let slot = slot(&parent, SELECTED);
	assert!(matches!(slot.observe(), Ok(SlotObservation::Absent)));

	fs::write(fixture.path(SELECTED), b"original").expect("create original");
	let original = present(&slot);
	assert_eq!(original.kind(), EntryKind::Regular);
	assert_eq!(original.identity().mount(), slot.parent_identity().mount());
	assert_eq!(original.recheck(), Ok(()));
	fixture.assert_debug_redacts(&slot, &[SELECTED]);
	fixture.assert_debug_redacts(&original, &[SELECTED]);

	fs::rename(fixture.path(SELECTED), fixture.path(OTHER)).expect("move fixture original aside");
	assert!(matches!(slot.observe(), Ok(SlotObservation::Absent)));
	assert_eq!(original.recheck(), Err(ObserveError::Changed));
	fs::write(fixture.path(SELECTED), b"replacement").expect("create replacement");
	let replacement = present(&slot);
	assert_ne!(
		replacement.identity().object(),
		original.identity().object()
	);
	assert_eq!(original.recheck(), Err(ObserveError::Changed));
	assert_eq!(
		fs::read(fixture.path(OTHER)).expect("read original"),
		b"original"
	);
	assert_eq!(
		fs::read(fixture.path(SELECTED)).expect("read replacement"),
		b"replacement"
	);
}

#[test]
fn reports_opaque_kind_without_following_or_opening_payload() {
	let fixture = Scratch::new();
	let parent = fixture.open();
	let slot = slot(&parent, SELECTED);
	symlink(fixture.path(OTHER), fixture.path(SELECTED)).expect("create dangling link");
	let link = present(&slot);
	assert_eq!(link.kind(), EntryKind::Symlink);
	assert_eq!(link.recheck(), Ok(()));
	assert!(!fixture.path(OTHER).exists());

	fs::remove_file(fixture.path(SELECTED)).expect("remove fixture link");
	fs::create_dir(fixture.path(SELECTED)).expect("create fixture directory");
	let directory = present(&slot);
	assert_eq!(directory.kind(), EntryKind::Directory);
	assert_eq!(link.recheck(), Err(ObserveError::Changed));
	fs::remove_dir(fixture.path(SELECTED)).expect("remove empty fixture directory");
	let _socket = UnixListener::bind(fixture.path(SELECTED)).expect("bind fixture socket");
	assert_eq!(present(&slot).kind(), EntryKind::Other);
	assert_eq!(directory.recheck(), Err(ObserveError::Changed));
}

#[test]
fn refuses_non_directory_and_previously_unlinked_parent() {
	let fixture = Scratch::new();
	let name = UnixComponent::new(SELECTED.as_bytes()).expect("synthetic component is valid");
	fs::write(fixture.path(OTHER), b"file").expect("create non-directory parent control");
	let file = File::open(fixture.path(OTHER)).expect("hold file");
	assert!(matches!(
		HeldSlot::from_authorized_parent(file.as_fd(), name),
		Err(ObserveError::InvalidParent)
	));

	fs::create_dir(fixture.path(SELECTED)).expect("create fixture directory");
	let parent = File::open(fixture.path(SELECTED)).expect("hold directory before unlink");
	let held = slot(&parent, OTHER);
	fs::remove_dir(fixture.path(SELECTED)).expect("unlink empty fixture directory");
	assert!(matches!(held.observe(), Err(ObserveError::InvalidParent)));
}

#[test]
fn distinguishes_hard_link_identity_from_distinct_slot_names() {
	let fixture = Scratch::new();
	let parent = fixture.open();
	let selected = slot(&parent, SELECTED);
	let other = slot(&parent, OTHER);
	fs::write(fixture.path(SELECTED), b"shared").expect("create fixture entry");
	fs::hard_link(fixture.path(SELECTED), fixture.path(OTHER)).expect("create fixture hard link");
	let first = present(&selected);
	let second = present(&other);
	assert_eq!(first.identity().object(), second.identity().object());
	assert_eq!(first.identity().mount(), second.identity().mount());
}

#[test]
fn refuses_unknown_entry_kind() {
	assert_eq!(
		entry_kind(FileType::Unknown),
		Err(ObserveError::UnavailableKind)
	);
}

#[test]
fn renamed_parent_survives_as_a_held_observation_only() {
	let fixture = Scratch::new();
	let parent_path = fixture.path("parent");
	let moved_path = fixture.path("moved");
	fs::create_dir(&parent_path).expect("create synthetic parent");
	fs::write(parent_path.join(SELECTED), b"original").expect("create original");
	let parent = File::open(&parent_path).expect("hold original parent");
	let original_slot = slot(&parent, SELECTED);
	let observed = present(&original_slot);

	fs::rename(&parent_path, &moved_path).expect("move the held fixture parent aside");
	fs::create_dir(&parent_path).expect("replace the original path");
	fs::write(parent_path.join(SELECTED), b"replacement").expect("create replacement");
	let replacement_parent = File::open(&parent_path).expect("hold replacement parent");
	let replacement_slot = slot(&replacement_parent, SELECTED);

	assert_eq!(observed.recheck(), Ok(()));
	assert_ne!(
		original_slot.parent_identity(),
		replacement_slot.parent_identity()
	);
	assert_ne!(
		observed.identity().object(),
		present(&replacement_slot).identity().object()
	);
}

mod mount;
