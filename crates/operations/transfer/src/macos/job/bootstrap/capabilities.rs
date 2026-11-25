use std::fs::File;

use exacopy_journal::{DarwinFileIdentity, OwnerError};

/// A newly created private job. Successful record and directory creation includes
/// the required file and namespace barriers.
pub(super) trait PrivateJob {
	type Error;
	type JournalDirectory<'job>: PrivateJournalDirectory<Error = Self::Error>
	where
		Self: 'job;

	fn owner_uid(&self) -> u32;
	fn identity(&self) -> Result<DarwinFileIdentity, OwnerError>;
	fn write_owner_record(&self, bytes: &[u8]) -> Result<(), Self::Error>;
	fn write_plan_record(&self, bytes: &[u8]) -> Result<(), Self::Error>;
	fn create_journal_directory(&self) -> Result<Self::JournalDirectory<'_>, Self::Error>;
}

/// A retained lease for the private journal namespace.
pub(super) trait PrivateJournalDirectory {
	type Error;

	/// Transfers the sole writer after exclusive creation and namespace synchronization.
	fn create_first_segment(&self) -> Result<File, Self::Error>;
}
