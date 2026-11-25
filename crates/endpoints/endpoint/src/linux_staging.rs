//! Capabilities for Linux's private, synchronous, single-file staging profile.

use exacopy_model::CopyBinding;

use crate::{IoError, ReadView, UnixComponent};

/// The result of a bounded probe for visible extended-attribute names.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ExtendedAttributes {
	/// The kernel did not report any visible names.
	NoneVisible,
	/// The kernel reported one or more visible names.
	Present,
	/// The filesystem or kernel could not provide a name list.
	Unsupported,
}

/// Captured source metadata for the Linux baseline preservation policy.
pub trait SourceMetadata: Copy {
	/// The observed timestamp type accepted by the metadata writer.
	type Timestamp: Copy;

	/// Returns the captured mode, including special permission bits.
	fn mode(self) -> u32;

	/// Returns the access timestamp captured before reading the source.
	fn accessed_at(self) -> Self::Timestamp;
}

/// A held regular source and its immutable admission observations.
pub trait StagingSource: ReadView {
	/// The physical file identity in the adapter's identity domain.
	type Identity: Copy + Eq;

	/// The captured metadata needed to preserve permissions and timestamps.
	type Metadata: SourceMetadata;

	/// Returns the identity of the held file.
	fn identity(&self) -> Self::Identity;

	/// Returns the metadata captured before reading the source.
	fn metadata(&self) -> Self::Metadata;

	/// Observes whether the adapter can confirm the absence of extended attributes.
	/// # Errors
	/// Returns an error when the bounded probe fails.
	fn extended_attributes(&self) -> Result<ExtendedAttributes, Self::Error>;

	/// Confirms the same captured inode and metadata without reading its data stream.
	/// # Errors
	/// Returns an error when the captured observation cannot be confirmed.
	fn recheck_metadata(&self) -> Result<(), Self::Error>;
}

/// A private directory that can exclusively allocate a new stage.
pub trait StagingDirectory<'stage> {
	/// The exclusive data writer bound to this directory.
	type Writer: StageWriter;

	/// Creates a private file bound to the target and attempt.
	/// # Errors
	/// Returns an error if the stage name is occupied or cannot be safely allocated.
	fn create_file(
		&'stage self,
		name: UnixComponent<'_>,
		target: UnixComponent<'_>,
		binding: CopyBinding,
	) -> Result<Self::Writer, <Self::Writer as StageWriter>::Error>;

	/// Synchronizes the private directory entries.
	/// # Errors
	/// Returns an error if directory identity or the barrier cannot be confirmed.
	fn sync_directory(&self) -> Result<(), <Self::Writer as StageWriter>::Error>;
}

/// The exclusive synchronous data writer for a newly allocated private file.
pub trait StageWriter {
	/// The physical file identity, in the same domain as the source and reader.
	type Identity: Copy + Eq;

	/// The source metadata needed to check ownership and preserve attributes.
	type Metadata: SourceMetadata;

	/// The adapter's stage operation error.
	type Error;

	/// The independently reopened, read-only handle for this stage.
	type Reader: StageReader<Identity = Self::Identity, Metadata = Self::Metadata, Error = Self::Error>;

	/// Returns the identity of the private file.
	fn identity(&self) -> Self::Identity;

	/// Confirms the existing UID and GID of the stage match the source.
	/// # Errors
	/// Returns an error when the identity or ownership cannot be confirmed.
	fn check_ownership(&self, metadata: Self::Metadata) -> Result<(), Self::Error>;

	/// Writes all bytes at the position synchronously within the bounded file extent.
	/// # Errors
	/// Returns an error for an unsupported range or an incomplete or failed write.
	fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Self::Error>;

	/// Sets the exact logical length before the final barrier.
	/// # Errors
	/// Returns an error for an unsupported length or failed resize.
	fn set_len(&mut self, length: u64) -> Result<(), Self::Error>;

	/// Completes the full file barrier for all writes so far.
	/// # Errors
	/// Returns an error when the stage cannot be confirmed or the barrier fails.
	fn flush(&mut self) -> Result<(), Self::Error>;

	/// Releases data-write authority and independently reopens the same stage for read-back.
	/// # Errors
	/// Returns an error if a current file barrier or the reopened stage cannot be confirmed.
	fn close_writes(self) -> Result<Self::Reader, Self::Error>;
}

/// A pinned private stage whose data writer has been released.
pub trait StageReader: Sized {
	/// The physical file identity, in the same domain as the source and writer.
	type Identity: Copy + Eq;

	/// The source metadata needed to preserve permissions and timestamps.
	type Metadata: SourceMetadata;

	/// The adapter's stage operation error.
	type Error;

	/// Returns the identity of the pinned stage.
	fn identity(&self) -> Self::Identity;

	/// Returns the logical byte length observed after release of data-write authority.
	fn length(&self) -> u64;

	/// Reads the full buffer at the position within the observed extent.
	/// # Errors
	/// Returns an error for an unsupported range or an incomplete or failed read.
	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), IoError>;

	/// Applies, reads back and synchronizes the required metadata without reopening data writes.
	/// # Errors
	/// Returns an error when the metadata, stage identity or file barrier cannot be confirmed.
	fn apply_metadata_with_access_time(
		self,
		metadata: Self::Metadata,
		accessed_at: <Self::Metadata as SourceMetadata>::Timestamp,
	) -> Result<Self, Self::Error>;

	/// Completes the barrier on the still-owned staging directory.
	/// # Errors
	/// Returns an error when directory identity or the barrier cannot be confirmed.
	fn sync_stage_directory(&self) -> Result<(), Self::Error>;
}
