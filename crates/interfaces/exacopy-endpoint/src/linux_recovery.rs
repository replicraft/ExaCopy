//! Read-only views of a held Linux recovery job and its selected namespace.

use std::io::Read;

use crate::linux_copy::CopySourceObservation;
use crate::linux_job::JobFileIdentity;
use crate::linux_staging::ExtendedAttributes;
use crate::{ReadView, UnixComponent};

/// A held recovery file that supports bounded sequential and positioned reads.
pub trait RecoveryRecord: Read + ReadView {
	/// The same native identity domain used to compare held files.
	type Identity: Copy + Eq + Into<JobFileIdentity>;

	/// Returns the observed device and inode.
	fn identity(&self) -> Self::Identity;

	/// Returns the metadata captured on the held file.
	fn observation(&self) -> CopySourceObservation;

	/// Rechecks the captured inode and metadata without reading the stream.
	/// # Errors
	/// Fails when the originally captured observation cannot be confirmed.
	fn recheck_inode(&self) -> Result<(), Self::Error>;

	/// Checks logical EOF at the captured extent without changing the sequential cursor.
	/// # Errors
	/// Fails if EOF or the current file cannot be confirmed.
	fn check_logical_eof(&self) -> Result<(), Self::Error>;

	/// Probes whether visible extended attributes are present.
	/// # Errors
	/// Fails when the bounded probe cannot complete.
	fn extended_attributes(&self) -> Result<ExtendedAttributes, Self::Error>;
}

/// A held job and destination namespace restricted to recovery observations.
pub trait RecoveryJobView {
	/// The read error from a held file.
	type ReadError;
	/// The namespace error when opening or checking a held object.
	type NamespaceError;
	/// The held read-only file.
	type Record: RecoveryRecord<Error = Self::ReadError>;
	/// An inventory that retains the checked stage and target observations.
	type Inventory<'job>: RecoveryInventoryView<Record = Self::Record, Error = Self::NamespaceError>
	where
		Self: 'job;

	/// Observes the private and destination directory identities.
	fn identities(&self) -> (JobFileIdentity, JobFileIdentity);

	/// Opens the private owner record.
	/// # Errors
	/// Fails if the named record cannot be held safely.
	fn open_owner(&self) -> Result<Self::Record, Self::NamespaceError>;

	/// Opens the canonical private plan.
	/// # Errors
	/// Fails if the named record cannot be held safely.
	fn open_plan(&self) -> Result<Self::Record, Self::NamespaceError>;

	/// Opens the first journal segment.
	/// # Errors
	/// Fails if the named segment cannot be held safely.
	fn open_first_segment(&self) -> Result<Self::Record, Self::NamespaceError>;

	/// Opens the bounded checkpoint page for one ordinal.
	/// # Errors
	/// Fails if the named page cannot be held safely.
	fn open_checkpoint(&self, ordinal: u32) -> Result<Self::Record, Self::NamespaceError>;

	/// Observes the fixed receipt name, distinguishing absence from lookup failure.
	/// # Errors
	/// Fails if the namespace observation cannot be established.
	fn open_optional_receipt(&self) -> Result<Option<Self::Record>, Self::NamespaceError>;

	/// Pins current namespace observations under the held job and its destination.
	/// # Errors
	/// Fails if either observation cannot be established safely.
	fn inventory(
		&self,
		stage: UnixComponent<'_>,
		target: UnixComponent<'_>,
	) -> Result<Self::Inventory<'_>, Self::NamespaceError>;
}

/// The pinned namespace observations of a held recovery job.
pub trait RecoveryInventoryView {
	/// The read-only file type.
	type Record: RecoveryRecord;
	/// The error from rechecking a namespace observation.
	type Error;

	/// Returns the checked private stage file, if present.
	fn stage(&self) -> Option<&Self::Record>;
	/// Returns the checked public target file, if present.
	fn target(&self) -> Option<&Self::Record>;
	/// Returns the identity of the held staging directory, if present.
	fn stage_directory_identity(&self) -> Option<JobFileIdentity>;

	/// Rechecks the originally observed names and directories.
	/// # Errors
	/// Fails if any relation or absence can no longer be confirmed.
	fn recheck(&self) -> Result<(), Self::Error>;
}

/// Read-only artifact observations for interrupted public-apply stage preparation.
pub trait PublicStageJobView: RecoveryJobView {
	/// Checks and opens the fixed owner record. `None` requires observed absence.
	/// # Errors
	/// Fails if absence or the held record cannot be established safely.
	fn open_optional_owner(&self) -> Result<Option<Self::Record>, Self::NamespaceError>;

	/// Checks and opens the fixed private plan. `None` requires observed absence.
	/// # Errors
	/// Fails if absence or the held record cannot be established safely.
	fn open_optional_plan(&self) -> Result<Option<Self::Record>, Self::NamespaceError>;

	/// Checks and opens the fixed first segment. `None` requires observed absence.
	/// # Errors
	/// Fails if absence or the held record cannot be established safely.
	fn open_optional_first_segment(&self) -> Result<Option<Self::Record>, Self::NamespaceError>;
}
