use std::ffi::CString;
use std::fmt;
use std::io;
use std::os::fd::BorrowedFd;

use apfs_mounted::metadata::{
	self as mounted, MetadataView, ObservationError, ResourceFork, XattrVisibility,
};
use apfs_mounted::source::SourceMetadata;
use rustix::fs::{FileType, Mode, Stat};

use super::{FILE_MODE, ManagedTimestamp, acl};

// Admission needs presence only. A positive kernel size exceeds this budget
// and the mounted library returns it before allocating or reading attribute data.
const PRESENCE_ONLY: usize = 0;

/// Required basic metadata for a strict managed transfer of one unnamed APFS stream.
///
/// Admission permits a one-link regular file with mode 0600, zero BSD flags,
/// no access-control entries or extended security GUIDs, no visible xattrs,
/// and no resource fork. Required fidelity covers the observed UID and GID,
/// mode, access time and modification time. The managed grant must cover the
/// process visibility limits and the selected source's required metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicMetadata {
	uid: u32,
	gid: u32,
	atime: ManagedTimestamp,
	mtime: ManagedTimestamp,
}

impl BasicMetadata {
	pub(super) fn from_stat(observed: &Stat) -> Result<Self, BasicMetadataError> {
		if FileType::from_raw_mode(observed.st_mode) != FileType::RegularFile
			|| Mode::from_raw_mode(observed.st_mode) != FILE_MODE
			|| observed.st_nlink != 1
			|| observed.st_flags != 0
		{
			return Err(BasicMetadataError::UnsupportedStat);
		}
		Ok(Self {
			uid: observed.st_uid,
			gid: observed.st_gid,
			atime: ManagedTimestamp::from_stat_parts(observed.st_atime, observed.st_atime_nsec)
				.ok_or(BasicMetadataError::Timestamp)?,
			mtime: ManagedTimestamp::from_stat_parts(observed.st_mtime, observed.st_mtime_nsec)
				.ok_or(BasicMetadataError::Timestamp)?,
		})
	}

	pub(super) fn from_mounted_source(
		observed: SourceMetadata,
	) -> Result<Self, BasicMetadataError> {
		if observed.mode != FILE_MODE.bits() || observed.link_count != 1 || observed.flags != 0 {
			return Err(BasicMetadataError::UnsupportedStat);
		}
		Ok(Self {
			uid: observed.owner,
			gid: observed.group,
			atime: ManagedTimestamp::from_mounted_source(observed.accessed),
			mtime: ManagedTimestamp::from_mounted_source(observed.modified),
		})
	}

	/// Returns the source owner's numeric UID.
	#[must_use]
	pub const fn uid(self) -> u32 {
		self.uid
	}

	/// Returns the source group owner's numeric GID.
	#[must_use]
	pub const fn gid(self) -> u32 {
		self.gid
	}

	/// Returns the permitted owner-private permission mode.
	#[must_use]
	pub const fn mode(self) -> u32 {
		FILE_MODE.bits() as u32
	}

	/// Returns the source access time captured before the transfer.
	#[must_use]
	pub const fn atime(self) -> ManagedTimestamp {
		self.atime
	}

	/// Returns the source modification time.
	#[must_use]
	pub const fn mtime(self) -> ManagedTimestamp {
		self.mtime
	}

	pub(super) fn matches(self, observed: &Stat) -> bool {
		Self::from_stat(observed).is_ok_and(|metadata| metadata == self)
	}
}

/// Reason a regular inode could not meet the strict basic metadata profile.
#[derive(Debug)]
#[non_exhaustive]
pub enum BasicMetadataError {
	/// The mode, type, link count or BSD flags are outside the basic profile.
	UnsupportedStat,
	/// A timestamp nanosecond field was unavailable or noncanonical.
	Timestamp,
	/// The ACL or extended security observation was ineligible.
	AccessControl,
	/// The descriptor exposes at least one extended attribute.
	ExtendedAttributes,
	/// The resource fork was present or its absence could not be established.
	ResourceFork,
	/// A descriptor inventory syscall failed.
	Inventory(io::Error),
}

impl fmt::Display for BasicMetadataError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::UnsupportedStat => formatter.write_str("unsupported mode, type, links or flags"),
			Self::Timestamp => formatter.write_str("invalid basic timestamp"),
			Self::AccessControl => formatter.write_str("ineligible extended security"),
			Self::ExtendedAttributes => formatter.write_str("visible extended attributes present"),
			Self::ResourceFork => {
				formatter.write_str("resource fork absence could not be confirmed")
			}
			Self::Inventory(error) => write!(formatter, "descriptor inventory failed ({error})"),
		}
	}
}

impl std::error::Error for BasicMetadataError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Inventory(error) => Some(error),
			_ => None,
		}
	}
}

pub(super) fn check_inventory(fd: BorrowedFd<'_>) -> Result<(), BasicMetadataError> {
	check_inventory_using(
		|| acl::has_basic_acl(fd),
		|| mounted::read_resource_fork(fd, PRESENCE_ONLY),
		|| mounted::resource_fork(fd),
		|visibility| mounted::list_xattrs(fd, visibility, PRESENCE_ONLY),
	)
}

pub(super) fn check_view_inventory(view: &MetadataView<'_>) -> Result<(), BasicMetadataError> {
	check_inventory_using(
		|| acl::basic_security(view.extended_security(mounted::MAX_EXTENDED_SECURITY_BYTES)),
		|| view.read_resource_fork(PRESENCE_ONLY),
		|| view.resource_fork(),
		|visibility| view.list_xattrs(visibility, PRESENCE_ONLY),
	)
}

fn check_inventory_using(
	basic_acl: impl FnOnce() -> io::Result<bool>,
	fork_attribute: impl FnOnce() -> Result<Option<Vec<u8>>, ObservationError>,
	fork: impl FnOnce() -> Result<ResourceFork, ObservationError>,
	list_attributes: impl Fn(XattrVisibility) -> Result<Vec<CString>, ObservationError>,
) -> Result<(), BasicMetadataError> {
	if !basic_acl().map_err(BasicMetadataError::Inventory)? {
		return Err(BasicMetadataError::AccessControl);
	}
	// A named fork is ineligible even when empty, before a length query.
	require_absent_fork_attribute(fork_attribute())?;
	match fork() {
		Ok(fork) if fork.confirmed_absent() => {}
		Ok(_) | Err(ObservationError::Malformed(_) | ObservationError::Limit { .. }) => {
			return Err(BasicMetadataError::ResourceFork);
		}
		Err(error) => return Err(BasicMetadataError::Inventory(observation_io_error(error))),
	}
	for visibility in [
		XattrVisibility::Visible,
		XattrVisibility::IncludingCompression,
	] {
		match list_attributes(visibility) {
			Ok(names) if names.is_empty() => {}
			Ok(_)
			| Err(ObservationError::Limit {
				limit: PRESENCE_ONLY,
				observed: 1..,
			}) => {
				return Err(BasicMetadataError::ExtendedAttributes);
			}
			Err(error) => return Err(BasicMetadataError::Inventory(observation_io_error(error))),
		}
	}
	Ok(())
}

fn require_absent_fork_attribute(
	attribute: Result<Option<Vec<u8>>, ObservationError>,
) -> Result<(), BasicMetadataError> {
	match attribute {
		Ok(None) => Ok(()),
		Ok(Some(_))
		| Err(ObservationError::Limit {
			limit: PRESENCE_ONLY,
			observed: 1..,
		}) => Err(BasicMetadataError::ResourceFork),
		Err(error) => Err(BasicMetadataError::Inventory(observation_io_error(error))),
	}
}

pub(super) fn observation_io_error(error: ObservationError) -> io::Error {
	match error {
		ObservationError::Io(error)
		| ObservationError::PermissionDenied(error)
		| ObservationError::Unsupported(error) => error,
		ObservationError::Allocation(error) => io::Error::new(io::ErrorKind::OutOfMemory, error),
		error => io::Error::new(io::ErrorKind::InvalidData, error),
	}
}

#[cfg(test)]
mod tests;
