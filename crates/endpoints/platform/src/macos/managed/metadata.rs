use std::fmt;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::ptr;

use rustix::fs::{FileType, Mode, Stat, Timespec, Timestamps};

use super::{FILE_MODE, ManagedTimestamp, acl};

const FIELD_BYTES: usize = size_of::<u32>();
const RETURNED_ATTR_BYTES: usize = size_of::<libc::attribute_set_t>();
const RESOURCE_OFFSET: usize = FIELD_BYTES + RETURNED_ATTR_BYTES;
const RESOURCE_BYTES: usize = RESOURCE_OFFSET + size_of::<libc::off_t>();
const RESOURCE_FORK: &std::ffi::CStr = c"com.apple.ResourceFork";

fn timespec(timestamp: ManagedTimestamp) -> Timespec {
	Timespec {
		tv_sec: timestamp.seconds(),
		tv_nsec: timestamp.nanoseconds().into(),
	}
}

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

	pub(super) fn times(self) -> Timestamps {
		Timestamps {
			last_access: timespec(self.atime),
			last_modification: timespec(self.mtime),
		}
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
	if !acl::has_basic_acl(fd).map_err(BasicMetadataError::Inventory)? {
		return Err(BasicMetadataError::AccessControl);
	}
	check_fork(fd)?;
	for options in [0, libc::XATTR_SHOWCOMPRESSION] {
		// SAFETY: The descriptor remains borrowed. A null buffer and a zero
		// size request only the bounded syscall's size result.
		let list_bytes = unsafe { libc::flistxattr(fd.as_raw_fd(), ptr::null_mut(), 0, options) };
		match list_bytes {
			0 => {}
			1.. => return Err(BasicMetadataError::ExtendedAttributes),
			_ => return Err(BasicMetadataError::Inventory(io::Error::last_os_error())),
		}
	}
	Ok(())
}

fn check_fork(fd: BorrowedFd<'_>) -> Result<(), BasicMetadataError> {
	// SAFETY: The descriptor and static attribute name remain valid throughout
	// this size-only query. A null buffer and zero size request no output bytes.
	let fork_bytes = unsafe {
		libc::fgetxattr(
			fd.as_raw_fd(),
			RESOURCE_FORK.as_ptr(),
			ptr::null_mut(),
			0,
			0,
			libc::XATTR_SHOWCOMPRESSION,
		)
	};
	if fork_bytes >= 0 {
		return Err(BasicMetadataError::ResourceFork);
	}
	let error = io::Error::last_os_error();
	if error.raw_os_error() != Some(libc::ENOATTR) {
		return Err(BasicMetadataError::Inventory(error));
	}

	let mut request = acl::attribute_request(libc::ATTR_CMN_RETURNED_ATTRS);
	request.fileattr = libc::ATTR_FILE_RSRCLENGTH;
	let mut buffer = ResourceBuffer([0; RESOURCE_BYTES]);
	// SAFETY: The request and the aligned fixed-size buffer are initialized,
	// writable and disjoint. The descriptor remains borrowed during the call
	// and Darwin retains neither pointer.
	let result = unsafe {
		libc::fgetattrlist(
			fd.as_raw_fd(),
			(&raw mut request).cast(),
			buffer.0.as_mut_ptr().cast(),
			buffer.0.len(),
			libc::FSOPT_REPORT_FULLSIZE,
		)
	};
	if result != 0 {
		return Err(BasicMetadataError::Inventory(io::Error::last_os_error()));
	}
	if !is_zero_fork(&buffer) {
		return Err(BasicMetadataError::ResourceFork);
	}
	Ok(())
}

#[repr(C, align(4))]
struct ResourceBuffer([u8; RESOURCE_BYTES]);

fn is_zero_fork(buffer: &ResourceBuffer) -> bool {
	let fields = [
		RESOURCE_BYTES as u32,
		libc::ATTR_CMN_RETURNED_ATTRS,
		0,
		0,
		libc::ATTR_FILE_RSRCLENGTH,
		0,
	];
	let (header, remainder) = buffer.0[..RESOURCE_OFFSET].as_chunks::<FIELD_BYTES>();
	header.len() == fields.len()
		&& remainder.is_empty()
		&& header
			.iter()
			.zip(fields)
			.all(|(actual, expected)| *actual == expected.to_ne_bytes())
		&& buffer.0[RESOURCE_OFFSET..] == [0; size_of::<libc::off_t>()]
}

#[cfg(test)]
mod tests;
