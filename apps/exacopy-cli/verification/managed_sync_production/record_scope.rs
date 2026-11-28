//! Two-profile custody control for the exact managed whole-ext4 fixture.

use std::fs::File;
use std::path::Path;

use exacopy_platform::linux::{SyncPreviewRoots, SyncProfileStore, SyncProfileStoreError};

use super::rig::{Sandbox, native_object, object, read};
use super::{ID, SLOT, TestResult};

pub(super) fn exercise(
	sandbox: &mut Sandbox,
	profile: &Path,
	profile_directory: &File,
	roots: &SyncPreviewRoots<'_>,
) -> TestResult {
	let original_store = SyncProfileStore::open(profile)?;
	let original = original_store.read(ID)?;
	let fixture = sandbox.directory.try_clone()?;
	let other_directory = sandbox.mkdir(&fixture, b"other-profile")?;
	sandbox.write_new(&other_directory, SLOT, original.bytes())?;
	let other_store = SyncProfileStore::open(&sandbox.path.join("other-profile"))?;
	let other = other_store.read(ID)?;
	assert_ne!(original_store.identity(), other_store.identity());
	assert_eq!(original.bytes(), other.bytes());

	let nested = sandbox.mkdir(profile_directory, b"nested-history")?;
	let history = original.open_history(&profile.join("nested-history"))?;
	assert_eq!(
		native_object(history.read_root().identity()),
		object(&nested.metadata()?)
	);
	other.recheck_history_scope(&history, roots)?;
	assert!(matches!(
		original.recheck_history_scope(&history, roots),
		Err(SyncProfileStoreError::OverlappingRoles)
	));
	assert_eq!(read(profile_directory, SLOT)?.as_slice(), original.bytes());
	assert_eq!(read(&other_directory, SLOT)?.as_slice(), other.bytes());
	Ok(())
}
