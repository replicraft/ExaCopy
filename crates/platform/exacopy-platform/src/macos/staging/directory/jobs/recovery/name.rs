use std::fs::File;
use std::io;

use apfs_mounted::{EntryName, stored_name};
use exacopy_endpoint::UnixComponent;

pub(super) fn matches(file: &File, name: UnixComponent<'_>) -> io::Result<bool> {
	match_stored(stored_name(file), name)
}

fn match_stored(observed: io::Result<EntryName>, name: UnixComponent<'_>) -> io::Result<bool> {
	match observed {
		Ok(observed) => Ok(observed.as_bytes() == name.as_bytes()),
		// Pomologie uses InvalidData without an errno when Darwin returned a
		// malformed or unavailable name. The existing caller sees a mismatch.
		Err(error)
			if error.kind() == io::ErrorKind::InvalidData && error.raw_os_error().is_none() =>
		{
			Ok(false)
		}
		Err(error) => Err(error),
	}
}

#[test]
fn stored_name_mismatch_is_distinct_from_syscall_failure() {
	let name = UnixComponent::new(b"private-\xff").unwrap();
	assert!(
		match_stored(
			EntryName::new(name.as_bytes()).map_err(io::Error::other),
			name
		)
		.unwrap()
	);
	assert!(
		!match_stored(
			EntryName::new(b"Private-\xff").map_err(io::Error::other),
			name
		)
		.unwrap()
	);
	assert!(!match_stored(Err(io::ErrorKind::InvalidData.into()), name).unwrap());
	let failure = match_stored(Err(io::Error::from_raw_os_error(libc::EIO)), name).unwrap_err();
	assert_eq!(failure.raw_os_error(), Some(libc::EIO));
}
