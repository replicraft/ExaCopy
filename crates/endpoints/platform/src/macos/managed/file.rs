use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::AsFd as _;
use std::os::unix::fs::FileExt as _;

use exacopy_endpoint::{MAX_INTERRUPTED_RETRIES, UnixComponent, read_exact_at};
use rustix::fs::{self, AtFlags, Stat};
use rustix::io::Errno;

use super::{
	BasicMetadata, ManagedObjectIdentity, ManagedReadError, ManagedTimestamp, PhysicalFsid,
	ReadDirectory, metadata, with_materialization_disabled,
};

/// Held native identities of a managed source and its independently admitted parent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedSourceIdentities {
	/// The source directory identity held by the lease.
	pub parent: ManagedObjectIdentity,
	/// The source file identity checked against the selected name.
	pub file: ManagedObjectIdentity,
}

/// A held, read-only view of a regular file beneath a managed APFS directory.
///
/// Reads are synchronous and positioned. Each calling thread establishes its
/// own dataless policy scope. Metadata checks report observations of a live
/// inode. Ordinary reads can update the access time.
pub struct ManagedRegularFile<'root> {
	root: ReadDirectory<'root>,
	name: UnixComponent<'root>,
	file: File,
	initial: Stat,
	length: u64,
}

impl fmt::Debug for ManagedRegularFile<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("ManagedRegularFile")
			.finish_non_exhaustive()
	}
}

impl<'root> ManagedRegularFile<'root> {
	pub(super) fn new(
		root: ReadDirectory<'root>,
		name: UnixComponent<'root>,
		file: File,
		initial: Stat,
		length: u64,
	) -> Self {
		Self {
			root,
			name,
			file,
			initial,
			length,
		}
	}

	/// Logical length of the unnamed byte stream at admission.
	#[must_use]
	pub fn length(&self) -> u64 {
		self.length
	}

	/// Whether the captured logical length was zero.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.length == 0
	}

	/// Revalidates the native identities of the selected file and its held parent.
	/// This observes metadata without reading file contents or probing EOF.
	/// # Errors
	/// Refuses changed identities, unavailable observations, or a failed policy check.
	pub fn observe_identities(&self) -> Result<ManagedSourceIdentities, ManagedReadError> {
		with_materialization_disabled(|| {
			self.root.check_root()?;
			self.check_file()?;
			let parent = self.root.identity.observe(self.root.directory)?;
			let file =
				ManagedObjectIdentity::from_stat(&self.initial, self.root.identity.physical_fsid)
					.ok_or(ManagedReadError::UnsupportedChild)?;
			Ok(ManagedSourceIdentities { parent, file })
		})
	}

	/// Returns the raw selected name bound to this held file.
	#[must_use]
	pub fn component(&self) -> UnixComponent<'_> {
		self.name
	}

	/// Returns the inode change time observed at descriptor admission.
	/// # Errors
	/// Refuses an unavailable or malformed timestamp.
	pub fn change_time(&self) -> Result<ManagedTimestamp, ManagedReadError> {
		ManagedTimestamp::from_stat_parts(self.initial.st_ctime, self.initial.st_ctime_nsec)
			.ok_or(ManagedReadError::UnsupportedChild)
	}

	/// Rechecks strict basic metadata and returns timestamps captured at admission.
	/// Call before transferring data. Later reads can advance the source access time.
	/// # Errors
	/// Refuses unavailable or changed identity, lease or strict basic metadata evidence.
	pub fn check_basic_metadata(&self) -> Result<BasicMetadata, ManagedReadError> {
		with_materialization_disabled(|| self.check_basic_metadata_with_policy())
	}

	pub(super) fn check_basic_metadata_with_policy(
		&self,
	) -> Result<BasicMetadata, ManagedReadError> {
		self.root.check_root()?;
		self.check_file()?;
		let metadata = BasicMetadata::from_stat(&self.initial)?;
		metadata::check_inventory(self.file.as_fd())?;
		self.root.check_root()?;
		self.check_file()?;
		Ok(metadata)
	}

	/// Read exactly the requested range of the captured extent.
	///
	/// # Errors
	///
	/// Returns a typed bounds, evidence, I/O or policy error. On error, the
	/// buffer may have changed and must be discarded.
	pub fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), ManagedReadError> {
		let count = u64::try_from(buffer.len()).map_err(|_| ManagedReadError::RangeOutsideFile)?;
		if offset
			.checked_add(count)
			.is_none_or(|end| end > self.length)
		{
			return Err(ManagedReadError::RangeOutsideFile);
		}
		with_materialization_disabled(|| {
			self.root.check_root()?;
			self.check_file()?;
			read_exact_at(offset, buffer, |position, unread| {
				self.file.read_at(unread, position)
			})
			.map_err(ManagedReadError::Read)?;
			self.root.check_root()?;
			self.check_file()
		})
	}

	/// Recheck held and named identity, root authority, and logical EOF.
	///
	/// Observes EOF with a positioned read at the captured logical length
	/// under the scoped dataless policy. The result is a live observation.
	///
	/// # Errors
	///
	/// Fails if metadata or authority changed, data is visible beyond the
	/// captured extent, or an I/O or thread policy check fails.
	pub fn revalidate(&self) -> Result<(), ManagedReadError> {
		with_materialization_disabled(|| {
			self.root.check_root()?;
			self.check_file()?;
			self.check_logical_eof()?;
			self.root.check_root()?;
			self.check_file()
		})
	}

	pub(super) fn check_file(&self) -> Result<(), ManagedReadError> {
		let held = fs::fstat(&self.file)?;
		let named = match fs::statat(
			self.root.directory,
			self.name.as_bytes(),
			AtFlags::SYMLINK_NOFOLLOW,
		) {
			Ok(stat) => stat,
			Err(Errno::NOENT) => return Err(ManagedReadError::SourceChanged),
			Err(error) => return Err(error.into()),
		};
		if !same_observation(&held, &self.initial)
			|| !same_observation(&named, &self.initial)
			|| PhysicalFsid::held(self.file.as_fd())? != Some(self.root.identity.physical_fsid)
			|| self.root.named_fsid(self.name)? != Some(self.root.identity.physical_fsid)
		{
			return Err(ManagedReadError::SourceChanged);
		}
		Ok(())
	}

	fn check_logical_eof(&self) -> Result<(), ManagedReadError> {
		let mut remaining_retries = MAX_INTERRUPTED_RETRIES;
		loop {
			match self.file.read_at(&mut [0], self.length) {
				Ok(0) => return Ok(()),
				Ok(_) => return Err(ManagedReadError::UnexpectedDataAfterEnd),
				Err(error)
					if error.kind() == io::ErrorKind::Interrupted && remaining_retries > 0 =>
				{
					remaining_retries -= 1;
				}
				Err(error) => return Err(error.into()),
			}
		}
	}
}

pub(super) fn same_observation(current: &Stat, initial: &Stat) -> bool {
	current.st_dev == initial.st_dev
		&& current.st_ino == initial.st_ino
		&& current.st_gen == initial.st_gen
		&& current.st_birthtime == initial.st_birthtime
		&& current.st_birthtime_nsec == initial.st_birthtime_nsec
		&& current.st_mode == initial.st_mode
		&& current.st_uid == initial.st_uid
		&& current.st_gid == initial.st_gid
		&& current.st_nlink == initial.st_nlink
		&& current.st_flags == initial.st_flags
		&& current.st_size == initial.st_size
		&& current.st_ctime == initial.st_ctime
		&& current.st_ctime_nsec == initial.st_ctime_nsec
		&& current.st_mtime == initial.st_mtime
		&& current.st_mtime_nsec == initial.st_mtime_nsec
}
