//! Read-only views of a held Linux recovery job and its selected namespace.

use std::io::Read;

use crate::linux_copy::{CopySourceObservation, InodeTimestamp};
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

/// Historical process-crash environment selected independently of the recovered job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyRecoveryEnvironment {
	/// Evaluated kernel boot ID.
	pub boot_id: [u8; 16],
	/// Evaluated process mount namespace.
	pub mount_namespace: u64,
	/// Exact unique identity of the evaluated mount.
	pub unique_mount: u64,
	/// Linux device number of that mount.
	pub device: u64,
}

/// Required preserve-mode facts selected by a complete stage seal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyRecoveryMetadata {
	/// Extent of the independently verified logical stream.
	pub length: u64,
	/// Exact ordinary permission bits.
	pub mode: u32,
	/// File owner.
	pub uid: u32,
	/// File group.
	pub gid: u32,
	/// Required preserved access time.
	pub accessed_at: InodeTimestamp,
	/// Required preserved modification time.
	pub modified_at: InodeTimestamp,
}

/// Exact names selected by the authenticated private Plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyNamesSelection<'name> {
	/// Private stage basename.
	pub stage: UnixComponent<'name>,
	/// Public target basename.
	pub target: UnixComponent<'name>,
	/// Historic stage identity from the accepted preparation, when present.
	pub candidate: Option<JobFileIdentity>,
	/// Native source root bound by the selected private Plan.
	pub source_root: JobFileIdentity,
	/// Environment bound by an actual accepted intent. No intent permits metadata only.
	pub environment: Option<ApplyRecoveryEnvironment>,
	/// Exact required metadata when verification and metadata frames are complete.
	pub required: Option<ApplyRecoveryMetadata>,
}

/// Native continuity established for this read-only observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyContinuity {
	/// No current qualified match to the selected historical environment was established.
	Unqualified,
	/// Actual held roots and current native facts match the historical profile and environment.
	MatchedQualifiedScope,
}

/// Current name evidence. Only a checked exact candidate admits reading data.
#[derive(Debug)]
pub enum ApplyNameObservation<'held, Record> {
	/// The selected name was absent.
	Absent,
	/// Metadata-only observation, with no data aperture.
	Present(JobFileIdentity),
	/// Checked original candidate and same-inode no-atime read aperture.
	Readable(&'held Record),
}

/// Fixed read-only records held together on one shared job lease.
pub trait HeldPublicApplyRecords {
	/// Held record implementation.
	type Record: RecoveryRecord;
	/// Exact error from checking the original fixed names or parents.
	type Error;

	/// The signed owner record, when observed present.
	fn owner(&self) -> Option<&Self::Record>;
	/// The canonical private Plan record, when observed present.
	fn plan(&self) -> Option<&Self::Record>;
	/// The held first segment starts at byte zero. Later borrows retain its
	/// current sequential cursor. Positioned reads leave that cursor unchanged.
	fn segment(&mut self) -> Option<&mut Self::Record>;
	/// The original opened receipt, when observed present.
	fn receipt(&self) -> Option<&Self::Record>;

	/// Rechecks all held names, parents, absences, captured facts and physical EOF.
	/// # Errors
	/// Refuses any unsafe, changed or unobservable artifact.
	fn recheck_records(&self) -> Result<(), Self::Error>;
}

/// Stage and target evidence held under the same protected read lease.
pub trait HeldPublicApplyNames {
	/// Read-only no-atime file with checked custody.
	type Record: RecoveryRecord;
	/// Exact cause of an unsafe or changed namespace.
	type Error;

	/// Current qualified continuity, when established.
	fn continuity(&self) -> ApplyContinuity;
	/// Current staging directory identity retained by this view.
	fn stage_directory_identity(&self) -> Option<JobFileIdentity>;
	/// Current private stage observation.
	fn stage(&self) -> ApplyNameObservation<'_, Self::Record>;
	/// Current public target observation.
	fn target(&self) -> ApplyNameObservation<'_, Self::Record>;

	/// Rechecks the original held directories, scope, names and expected metadata.
	/// # Errors
	/// Refuses change, native mismatch or a failed observation.
	fn recheck_names(&self) -> Result<(), Self::Error>;
}

/// Actual held shared read lease restricted to public-apply reconciliation.
pub trait PublicApplyReadView {
	/// Held read-only records.
	type Record: RecoveryRecord;
	/// Exact platform error for names, records or the lease.
	type Error;
	/// Fixed record custody bounded by this original view.
	type Records<'view>: HeldPublicApplyRecords<Record = Self::Record, Error = Self::Error>
	where
		Self: 'view;
	/// Name aperture bounded by this original view.
	type Names<'view>: HeldPublicApplyNames<Record = Self::Record, Error = Self::Error>
	where
		Self: 'view;

	/// Reports held job and destination identities.
	fn identities(&self) -> (JobFileIdentity, JobFileIdentity);

	/// Holds the original fixed records and both subordinate parent directories.
	/// # Errors
	/// Refuses unsafe namespace, wrong custody or observable record changes.
	fn hold_apply_records(&self) -> Result<Self::Records<'_>, Self::Error>;

	/// Pins actual stage and target names. No data reads occur in this call.
	/// # Errors
	/// Refuses failed lookup, unsupported namespace semantics or unstable evidence.
	fn pin_apply_names(
		&self,
		selected: ApplyNamesSelection<'_>,
	) -> Result<Self::Names<'_>, Self::Error>;

	/// Opens one bounded immutable checkpoint referenced by the accepted journal.
	/// # Errors
	/// Refuses unsafe or unavailable checkpoint evidence.
	fn open_apply_checkpoint(&self, ordinal: u32) -> Result<Self::Record, Self::Error>;
}
