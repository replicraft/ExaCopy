//! macOS capability discovery for selecting one local regular file.
//!
//! Darwin's `openat` can reject a symlink, but it has no regular-file-only
//! open flag. A preliminary type check cannot protect a later name lookup
//! against replacement by a special file. `O_EVTONLY` is documented for
//! event notifications, and `/dev/fd` duplicates descriptors with existing
//! access rights. A metadata probe cannot authorize a readable open.
//! Independently provisioned directories can use the explicit [ManagedReadRoot]
//! capability with a trusted-owner grant and checked local APFS evidence.
//!
//! The caller supplies a held, materialized directory on a local filesystem
//! outside File Provider-managed namespaces. A lookup through a dataless
//! directory can trigger materialization. See Apple's [dataless file guidance].
//!
//! See Apple's [`open(2)`] documentation and the macOS `fd(4)` manual.
//!
//! [`open(2)`]: https://github.com/apple/darwin-xnu/blob/main/bsd/man/man2/open.2
//! [dataless file guidance]: https://developer.apple.com/documentation/technotes/tn3150-getting-ready-for-data-less-files

use std::fmt;
use std::fs::File;
use std::io;

use exacopy_endpoint::UnixComponent;
use rustix::fs::{self, AtFlags, Dev, FileType};
use rustix::io::Errno;

mod managed;

#[cfg(test)]
mod tests;

pub use managed::{ManagedReadError, ManagedReadGrant, ManagedReadRoot, ManagedRegularFile};

/// A held directory for metadata probes on macOS.
pub struct ReadRoot {
	directory: File,
	device: Dev,
}

impl fmt::Debug for ReadRoot {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.debug_struct("ReadRoot").finish_non_exhaustive()
	}
}

/// Why a probe could not inspect a child of the held directory.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProbeError {
	/// The supplied root descriptor refers to an object other than a directory.
	NotDirectory,
	/// The operating system could not inspect the root or child.
	System(io::Error),
}

impl fmt::Display for ProbeError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::NotDirectory => formatter.write_str("read root must be a directory"),
			Self::System(error) => write!(formatter, "file metadata probe failed ({error})"),
		}
	}
}

impl std::error::Error for ProbeError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::NotDirectory => None,
			Self::System(error) => Some(error),
		}
	}
}

impl From<Errno> for ProbeError {
	fn from(error: Errno) -> Self {
		Self::System(error.into())
	}
}

/// The outcome of a metadata-only child probe. No outcome grants read access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegularFileProbe {
	/// The name did not exist under the held directory at the time of the probe.
	Missing,
	/// The name referred to a symbolic link, whose target was never resolved.
	SymbolicLink,
	/// The name referred to a directory or some other non-regular entry.
	NotRegularFile,
	/// The child metadata had a different device identifier from the root.
	DifferentDevice,
	/// A regular file was observed, but no supported pinned readable open is available.
	PinnedReadOpenUnavailable,
}

impl ReadRoot {
	/// Bind an already authorized directory descriptor for capability discovery.
	/// The caller must establish that the directory is materialized, on a local
	/// filesystem and outside File Provider-managed namespaces for every probe.
	///
	/// # Errors
	/// Fails if the descriptor cannot be inspected or refers to a non-directory.
	pub fn from_directory(directory: File) -> Result<Self, ProbeError> {
		let stat = fs::fstat(&directory)?;
		if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
			return Err(ProbeError::NotDirectory);
		}
		Ok(Self {
			directory,
			device: stat.st_dev,
		})
	}

	/// Inspect a single child name relative to the held directory without opening it.
	///
	/// The final name can change as soon as the kernel returns its metadata.
	/// Device identifiers can exclude a different device but do not establish
	/// full mount containment. The probe returns no file handle or read authority.
	///
	/// # Errors
	/// Fails on filesystem errors other than an absent name.
	pub fn probe_regular_file(
		&self,
		name: UnixComponent<'_>,
	) -> Result<RegularFileProbe, ProbeError> {
		let stat = match fs::statat(&self.directory, name.as_bytes(), AtFlags::SYMLINK_NOFOLLOW) {
			Ok(stat) => stat,
			Err(Errno::NOENT) => return Ok(RegularFileProbe::Missing),
			Err(error) => return Err(error.into()),
		};
		if stat.st_dev != self.device {
			return Ok(RegularFileProbe::DifferentDevice);
		}
		Ok(match FileType::from_raw_mode(stat.st_mode) {
			FileType::RegularFile => RegularFileProbe::PinnedReadOpenUnavailable,
			FileType::Symlink => RegularFileProbe::SymbolicLink,
			_ => RegularFileProbe::NotRegularFile,
		})
	}
}
