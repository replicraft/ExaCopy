use std::fmt;

use apfs_mounted::source::{MAX_READ_BYTES, PinnedSource};
use exacopy_endpoint::{ReadView, UnixComponent};
use rustix::fs::Stat;

use super::{
	BasicMetadata, ManagedObjectIdentity, ManagedReadError, ManagedTimestamp, ReadDirectory, error,
	metadata, with_materialization_disabled,
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
	source: PinnedSource<'root>,
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
		source: PinnedSource<'root>,
	) -> Self {
		Self { root, name, source }
	}

	/// Logical length of the unnamed byte stream at admission.
	#[must_use]
	pub fn length(&self) -> u64 {
		self.source.len()
	}

	/// Whether the captured logical length was zero.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.source.is_empty()
	}

	/// Revalidates the native identities of the selected file and its held parent.
	/// This observes metadata without reading file contents or probing EOF.
	/// # Errors
	/// Refuses changed identities, unavailable observations, or a failed policy check.
	pub fn observe_identities(&self) -> Result<ManagedSourceIdentities, ManagedReadError> {
		with_materialization_disabled(|| {
			self.root.check_root()?;
			self.source.validate().map_err(error::source_error)?;
			let parent = ManagedObjectIdentity::from_mounted(self.source.parent_identity());
			let file = ManagedObjectIdentity::from_mounted(self.source.identity());
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
		Ok(ManagedTimestamp::from_mounted_source(
			self.source.metadata().changed,
		))
	}

	/// Rechecks strict basic metadata and returns timestamps captured at admission.
	/// Call before transferring data. Later reads can advance the source access time.
	/// # Errors
	/// Refuses unavailable or changed identity, lease or strict basic metadata evidence.
	pub fn check_basic_metadata(&self) -> Result<BasicMetadata, ManagedReadError> {
		with_materialization_disabled(|| self.check_basic_metadata_with_policy())
	}

	/// Rechecks strict basic metadata and the original access time before content reads.
	///
	/// Call immediately before starting a managed copy to confirm that the captured
	/// access time still applies.
	///
	/// # Errors
	/// Refuses changed access time, unavailable evidence, or any strict metadata failure.
	pub fn check_pre_read_basic_metadata(&self) -> Result<BasicMetadata, ManagedReadError> {
		with_materialization_disabled(|| {
			let metadata = self.check_basic_metadata_with_policy()?;
			let access_time = self
				.source
				.with_metadata(|view| Ok(view.stat()?.times.access))
				.map_err(error::source_error)?;
			if access_time.seconds() != metadata.atime().seconds()
				|| access_time.nanoseconds() != i64::from(metadata.atime().nanoseconds())
			{
				return Err(ManagedReadError::SourceChanged);
			}
			Ok(metadata)
		})
	}

	pub(super) fn check_basic_metadata_with_policy(
		&self,
	) -> Result<BasicMetadata, ManagedReadError> {
		self.root.check_root()?;
		self.source.validate().map_err(error::source_error)?;
		let metadata = BasicMetadata::from_mounted_source(self.source.metadata())?;
		self.source
			.with_metadata(|view| Ok(metadata::check_view_inventory(&view)))
			.map_err(error::source_error)??;
		self.root.check_root()?;
		Ok(metadata)
	}

	/// Read exactly the requested range of the captured extent.
	///
	/// # Errors
	///
	/// Returns a typed bounds, evidence, I/O or policy error. On error, the
	/// buffer may have changed and must be discarded.
	pub fn read_exact_at(
		&self,
		mut offset: u64,
		buffer: &mut [u8],
	) -> Result<(), ManagedReadError> {
		let count = u64::try_from(buffer.len()).map_err(|_| ManagedReadError::RangeOutsideFile)?;
		if offset
			.checked_add(count)
			.is_none_or(|end| end > self.length())
		{
			return Err(ManagedReadError::RangeOutsideFile);
		}
		with_materialization_disabled(|| {
			self.root.check_root()?;
			if buffer.is_empty() {
				self.source.validate().map_err(error::source_error)?;
			}
			for request in buffer.chunks_mut(MAX_READ_BYTES) {
				self.source
					.read_exact_at(offset, request)
					.map_err(|error| error::source_read_error(error, offset, request.len()))?;
				// The full range was checked above. Each chunk ends within it.
				offset += request.len() as u64;
			}
			self.root.check_root()
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
			self.source.revalidate().map_err(error::source_error)?;
			self.root.check_root()
		})
	}
}

impl ReadView for ManagedRegularFile<'_> {
	type Error = ManagedReadError;

	fn length(&self) -> u64 {
		ManagedRegularFile::length(self)
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.revalidate()
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		ManagedRegularFile::read_exact_at(self, offset, buffer)
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
