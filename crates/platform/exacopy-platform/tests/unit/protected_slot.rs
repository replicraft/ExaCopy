use std::error::Error;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;

use exacopy_endpoint::UnixComponent;
use rustix::io::Errno;

use crate::linux::protected_slot::{EntryKind, HeldSlot, ObserveError};
use crate::scratch::Scratch;

use super::{OTHER, SELECTED, present, slot};

#[test]
fn observes_the_exact_unix_component_bytes() {
	const RAW_NAME: &[u8] = b"child-\xff";
	const LOSSY_NAME: &str = "child-\u{fffd}";

	let fixture = Scratch::new();
	let parent = fixture.open();
	let raw_path = fixture.path(OsStr::from_bytes(RAW_NAME));
	let lossy_path = fixture.path(LOSSY_NAME);
	fs::write(&raw_path, b"raw").expect("create raw-name entry");
	fs::write(&lossy_path, b"lossy").expect("create the distinct lossy spelling");
	let raw_metadata = fs::metadata(&raw_path).expect("identify raw-name entry");
	let lossy_metadata = fs::metadata(&lossy_path).expect("identify lossy-name control");
	assert_ne!(raw_metadata.ino(), lossy_metadata.ino());

	let raw_slot = HeldSlot::from_authorized_parent(
		parent.as_fd(),
		UnixComponent::new(RAW_NAME).expect("raw name is a valid Unix component"),
	)
	.expect("hold synthetic parent for the raw component");
	let entry = present(&raw_slot);
	assert_eq!(entry.kind(), EntryKind::Regular);
	assert_eq!(entry.identity().object().device(), raw_metadata.dev());
	assert_eq!(entry.identity().object().inode(), raw_metadata.ino());
	assert_eq!(entry.recheck(), Ok(()));
}

#[test]
fn pinned_recheck_propagates_invalid_parent() {
	let fixture = Scratch::new();
	let parent_path = fixture.path(OTHER);
	let entry_path = parent_path.join(SELECTED);
	fs::create_dir(&parent_path).expect("create synthetic parent");
	fs::write(&entry_path, b"fixture entry").expect("create synthetic occupant");
	let parent = File::open(&parent_path).expect("hold synthetic parent");
	let slot = slot(&parent, SELECTED);
	let entry = present(&slot);
	assert_eq!(entry.recheck(), Ok(()));

	fs::remove_file(&entry_path).expect("remove synthetic occupant");
	assert_eq!(entry.recheck(), Err(ObserveError::Changed));
	fs::remove_dir(&parent_path).expect("unlink empty synthetic parent");
	assert_eq!(entry.recheck(), Err(ObserveError::InvalidParent));
}

#[test]
fn observation_error_reports_keep_typed_causes() {
	let cases = [
		(
			ObserveError::InvalidParent,
			"slot parent is not a live directory",
		),
		(
			ObserveError::UnavailableIdentity,
			"native slot identity is unavailable",
		),
		(
			ObserveError::UnavailableKind,
			"native slot entry kind is unavailable",
		),
		(ObserveError::CrossedMount, "slot lookup crossed a mount"),
		(ObserveError::Changed, "held slot observation changed"),
	];
	for (error, diagnostic) in cases {
		assert_eq!(error.to_string(), diagnostic, "{error:?}");
		assert!(error.source().is_none(), "{error:?} has no native cause");
	}

	let native = Errno::ACCESS;
	let error = ObserveError::from(native);
	assert_eq!(error, ObserveError::Io(native));
	assert_eq!(
		error.to_string(),
		format!("native slot observation failed ({native})")
	);
	assert_eq!(
		error
			.source()
			.and_then(|source| source.downcast_ref::<Errno>()),
		Some(&native)
	);
}
