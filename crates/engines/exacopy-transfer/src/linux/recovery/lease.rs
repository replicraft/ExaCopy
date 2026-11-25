use exacopy_endpoint::linux_publication::ExclusivePublication;
use exacopy_endpoint::linux_recovery::{RecoveryJobView, RecoveryRecord};
use exacopy_endpoint::linux_staging::SourceMetadata;
use exacopy_endpoint::{JournalSegment, ReadView};
use exacopy_journal::{DurableJournal, ObservedTimestamp};
use exacopy_model::CopyBinding;

pub use super::finish::{FinishReceiptDirectory, ReceiptLease};
pub use super::resume::ResumeStageDirectory;

/// The native read cause carried by the held recovery file.
pub type LeaseReadError<L> = <<L as RecoveryLease>::File as ReadView>::Error;

/// The two held names observed inside this lease.
pub type LeaseInventory<'lease, L> =
	<<L as RecoveryLease>::Job<'lease> as RecoveryJobView>::Inventory<'lease>;

pub(super) type RecoveryJournal<'lease, L> = DurableJournal<<L as RecoveryLease>::Segment<'lease>>;

/// The exclusive job lease needed to complete a previously observed publication.
pub trait RecoveryLease: ReceiptLease<ExistingReceipt = Self::File> {
	/// The read-only recovery record and stream capability.
	type File: RecoveryRecord;
	/// The exclusive, append-only segment bound to the live recovery lease.
	type Segment<'lease>: JournalSegment
	where
		Self: 'lease;
	/// The held view of the same job directory under the exclusive lease.
	type Job<'lease>: RecoveryJobView<
			Record = Self::File,
			ReadError = LeaseReadError<Self>,
			NamespaceError = Self::EffectError,
		>
	where
		Self: 'lease;

	/// Returns the held job observed under this lease.
	fn job(&self) -> &Self::Job<'_>;

	/// Reopens the authorized journal for append at the same inode.
	/// # Errors
	/// Fails if the lease or retained segment can no longer be confirmed.
	fn open_segment(&self, file: &Self::File) -> Result<Self::Segment<'_>, Self::EffectError>;

	/// Applies supported barriers after a completed publication.
	/// # Errors
	/// Fails if the published observation or any required barrier cannot be confirmed.
	fn synchronize_publication<'lease>(
		&'lease self,
		names: &LeaseInventory<'lease, Self>,
	) -> Result<(), Self::EffectError>;
}

/// The held private stage capabilities for retained retry and partial resume.
pub trait RecoveryStageLease: RecoveryLease {
	/// Metadata accepted by writers for this held job.
	type Metadata: SourceMetadata;
	/// The native exclusive publication cause.
	type PublishError;

	/// A synchronized private stage that can consume one publication authorization.
	type Publisher<'lease>: ExclusivePublication<Error = Self::PublishError>
	where
		Self: 'lease;

	/// A safely reopened stage directory scoped to writing or reading its one retained file.
	type ResumeDirectory<'lease>: ResumeStageDirectory<
			Self::Metadata,
			<Self::File as RecoveryRecord>::Identity,
			Error = Self::EffectError,
			PublicationError = Self::PublishError,
		>
	where
		Self: 'lease;

	/// Rechecks and synchronizes the retained stage before offering exclusive publication.
	/// # Errors
	/// Fails if the lease, retained stage binding, or barrier cannot be confirmed.
	fn prepare_retry<'lease, 'inventory: 'lease>(
		&'lease self,
		names: &'lease LeaseInventory<'inventory, Self>,
		binding: CopyBinding,
	) -> Result<Self::Publisher<'lease>, Self::EffectError>
	where
		Self: 'inventory;

	/// Reopens the checked directory holding the retained stage.
	/// # Errors
	/// Fails if the lease or directory binding cannot be confirmed.
	fn reopen_stage<'lease, 'inventory: 'lease>(
		&'lease self,
		names: &'lease LeaseInventory<'inventory, Self>,
	) -> Result<Self::ResumeDirectory<'lease>, Self::EffectError>
	where
		Self: 'inventory;

	/// Validates the recorded access time in the adapter's metadata representation.
	/// # Errors
	/// Fails if the timestamp cannot be represented.
	fn source_timestamp(
		observed: ObservedTimestamp,
	) -> Result<<Self::Metadata as SourceMetadata>::Timestamp, LeaseReadError<Self>>;

	/// Returns whether the native cause is a confirmed incumbent conflict.
	fn is_conflict(error: &Self::PublishError) -> bool;
}
