use std::io;
use std::os::fd::BorrowedFd;

use apfs_mounted::{Directory, EntryName, IdentityError, ObjectIdentity};
use exacopy_endpoint::UnixComponent;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PhysicalFsid([u32; 2]);

impl PhysicalFsid {
	pub(super) const fn words(self) -> [u32; 2] {
		self.0
	}

	pub(super) fn held(fd: BorrowedFd<'_>) -> io::Result<Option<Self>> {
		project(ObjectIdentity::held(fd).map(Some))
	}

	pub(super) fn named(
		directory: BorrowedFd<'_>,
		name: UnixComponent<'_>,
	) -> io::Result<Option<Self>> {
		let name = EntryName::new(name.as_bytes())
			.map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
		// Duplicate the authorized descriptor. Name observation must remain
		// relative to the held directory, including when its path has moved.
		let directory = Directory::from_owned_fd(directory.try_clone_to_owned()?)?;
		let observation = ObjectIdentity::named(&directory, &name);
		if matches!(observation, Ok(None)) {
			return Err(rustix::io::Errno::NOENT.into());
		}
		project(observation)
	}
}

fn project(
	observation: Result<Option<ObjectIdentity>, IdentityError>,
) -> io::Result<Option<PhysicalFsid>> {
	match observation {
		Ok(observed) => Ok(observed.map(|identity| PhysicalFsid(identity.physical_fsid()))),
		Err(IdentityError::Unavailable | IdentityError::Changed) => Ok(None),
		Err(IdentityError::Io(error)) => Err(error),
		Err(error) => Err(io::Error::other(error)),
	}
}

#[test]
fn preserves_unavailable_identity_and_native_errors() {
	assert_eq!(project(Err(IdentityError::Unavailable)).unwrap(), None);
	assert_eq!(project(Err(IdentityError::Changed)).unwrap(), None);
	let denied = rustix::io::Errno::ACCESS;
	let error = project(Err(IdentityError::Io(denied.into()))).unwrap_err();
	assert_eq!(error.raw_os_error(), Some(denied.raw_os_error()));
}
