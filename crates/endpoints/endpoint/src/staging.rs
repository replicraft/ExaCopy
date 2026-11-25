use crate::ReadView;

/// Exclusive, sequential write access to a private stage with a declared extent.
///
/// Implementations retain the private entry when this capability is dropped or a
/// method fails. This capability has no source or public-name mutation operation.
pub trait FreshStage {
	/// The adapter's error when a stage operation fails.
	type Error;
	/// The same stage after the required data barrier and confirmed writer closure.
	type Closed: ClosedStage<Error = Self::Error>;

	/// Maximum chunk size for both writes and the independent read-back.
	const MAX_CHUNK_BYTES: usize;

	/// Returns the declared extent after confirming the stage is held and unwritten.
	///
	/// # Errors
	/// Refuses a stage that has changed, has started writing, or cannot be checked.
	fn unwritten_length(&self) -> Result<u64, Self::Error>;

	/// Writes the next chunk in full within the declared extent.
	///
	/// # Errors
	/// Returns an error if identity, bounds, or completion cannot be confirmed.
	/// A failed write may leave a prefix in the private stage.
	fn write_next(&mut self, buffer: &[u8]) -> Result<(), Self::Error>;

	/// Completes the required data barrier and confirms the writer closed.
	///
	/// # Errors
	/// Returns an error if the complete extent, barrier or writer closure is uncertain.
	fn sync_and_close(self) -> Result<Self::Closed, Self::Error>;
}

/// A private stage held for read-back after the data barrier and writer closure.
pub trait ClosedStage {
	/// The adapter's error when opening or reading the closed stage.
	type Error;
	/// An independently opened read-only view bound to this stage.
	type Reader<'stage>: ReadView<Error = Self::Error>
	where
		Self: 'stage;

	/// Opens a read-only view of the same staged stream with its declared extent.
	///
	/// # Errors
	/// Returns an error if the read-only view cannot be bound to the closed stage.
	fn open_read_back(&self) -> Result<Self::Reader<'_>, Self::Error>;
}

/// A read-only source that can be checked against a required metadata profile.
pub trait MetadataSource: ReadView {
	/// Checks that the same source can supply all metadata required by the profile.
	///
	/// # Errors
	/// Returns an error for changed, unsupported or unavailable metadata.
	fn admit_metadata(&self) -> Result<(), Self::Error>;
}

/// A closed stage that can synchronize and confirm required metadata from its source.
pub trait RequiredMetadataStage<S: MetadataSource>: ClosedStage {
	/// The same private stage with the profile's metadata read back and synchronized.
	type Ready;

	/// Applies the profile's metadata after successful independent stream verification.
	///
	/// The caller supplies the same source capability used to copy and measure the data.
	///
	/// # Errors
	/// Refuses changed observations and any incomplete metadata application, read-back or barrier.
	fn apply_metadata(self, source: &S) -> Result<Self::Ready, Self::Error>;
}
