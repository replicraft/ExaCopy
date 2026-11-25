use exacopy_endpoint::JournalSegment;

use exacopy_journal::{DarwinFileIdentity, OwnerError};

/// A newly created private job. Successful record and directory creation includes
/// the required file and namespace barriers.
pub trait PrivateJob {
	/// The adapter failure retained for diagnostics.
	type Error;
	/// The journal directory lease borrowing the private job.
	type JournalDirectory<'job>: PrivateJournalDirectory<Error = Self::Error>
	where
		Self: 'job;

	/// Returns the owner checked while creating the held job directory.
	fn owner_uid(&self) -> u32;
	/// Returns the identity bound while creating the held job directory.
	fn identity(&self) -> Result<DarwinFileIdentity, OwnerError>;
	/// Exclusively creates and synchronizes the signed owner envelope.
	fn write_owner_record(&self, bytes: &[u8]) -> Result<(), Self::Error>;
	/// Exclusively creates and synchronizes the canonical plan bytes.
	fn write_plan_record(&self, bytes: &[u8]) -> Result<(), Self::Error>;
	/// Exclusively creates and synchronizes the first-segment namespace.
	fn create_journal_directory(&self) -> Result<Self::JournalDirectory<'_>, Self::Error>;
}

/// A retained lease for the private journal namespace.
pub trait PrivateJournalDirectory {
	/// The adapter failure retained for diagnostics.
	type Error;

	/// The sole writer that retains this namespace after creation.
	type Segment: JournalSegment;

	/// Consumes the lease and transfers the sole writer after creation and synchronization.
	fn create_first_segment(self) -> Result<Self::Segment, Self::Error>;
}
