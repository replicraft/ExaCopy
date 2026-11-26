use std::mem::MaybeUninit;
use std::os::fd::AsFd;

use exacopy_endpoint::UnixComponent;
use rustix::fs::{self, Mode, OFlags, RawDir};

use super::{CHILD_RESOLUTION, FileIdentity, SyncPreviewError};

// Bound each exact-name confirmation, including the zero-match absence case.
pub(super) const MAX_DIRECTORY_ENTRIES: usize = 4096;
const DIRECTORY_SCRATCH_BYTES: usize = 4096;

// A casefolded or case-insensitive lookup can resolve a differently spelled
// entry. Compare raw dirent bytes and the held inode independently of lookup.
pub(super) fn confirm(
	parent: impl AsFd,
	name: UnixComponent<'_>,
	expected: Option<FileIdentity>,
) -> Result<(), SyncPreviewError> {
	let readable = fs::openat2(
		parent,
		c".",
		OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
		Mode::empty(),
		CHILD_RESOLUTION,
	)?;
	// Use RawDir so an error such as ENOENT on a detached directory cannot
	// become a successfully exhausted scan. The supported filesystems bound
	// each entry by the validated platform component size plus its header.
	let mut scratch = [MaybeUninit::uninit(); DIRECTORY_SCRATCH_BYTES];
	let mut entries = RawDir::new(readable, &mut scratch);
	for index in 0..=MAX_DIRECTORY_ENTRIES {
		let Some(entry) = entries.next() else {
			return if expected.is_some() {
				Err(SyncPreviewError::NameAlias)
			} else {
				Ok(())
			};
		};
		if index == MAX_DIRECTORY_ENTRIES {
			return Err(SyncPreviewError::DirectoryLimit);
		}
		let entry = entry?;
		if entry.file_name().to_bytes() == name.as_bytes() {
			return if expected.is_some_and(|identity| identity.inode() == entry.ino()) {
				Ok(())
			} else {
				Err(SyncPreviewError::Changed)
			};
		}
	}
	Err(SyncPreviewError::DirectoryLimit)
}
