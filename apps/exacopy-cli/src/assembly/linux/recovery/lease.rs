use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_publication::{ExclusivePublication, PublicationFailure};
use exacopy_journal::{LinuxFileIdentity, ObservedTimestamp};
use exacopy_model::{CopyBinding, PublishNoClobber};
use exacopy_platform::linux::{
	ClosedStage, DestinationRoot, FileIdentity, LinuxJournalSegment, NativeReceiptRecord,
	PublishError, ReadError, RecoveryFile, RecoveryJob, RecoveryReceiptDirectory,
	RecoveryStageDirectory, RecoveryWriteLease, RetainedStage, SourceObservation, SourceTimestamp,
	StageError, WriteStage,
};
use exacopy_transfer::linux::{
	CopyCheckpoint, FinishReceiptDirectory, InspectionError, LeaseInventory, ReceiptLease,
	RecoveryLease, RecoveryStageLease, RecoveryStep, ResumeStageDirectory,
};

use super::RecoveryInspectError;

pub(super) struct NativeLease<'root>(RecoveryWriteLease<'root>);

impl<'root> NativeLease<'root> {
	pub(super) fn acquire(
		destination: &'root DestinationRoot,
		name: UnixComponent<'_>,
	) -> Result<Self, RecoveryInspectError> {
		let previous =
			destination
				.open_recovery_job(name)
				.map_err(|source| InspectionError::Platform {
					step: RecoveryStep::Job,
					source,
				})?;
		destination
			.try_recovery_write_lease(name, previous.identity())
			.map(Self)
			.map_err(|source| InspectionError::Platform {
				step: RecoveryStep::Lease,
				source,
			})
	}
}

impl RecoveryLease for NativeLease<'_> {
	type File = RecoveryFile;
	type Segment<'lease>
		= LinuxJournalSegment<'lease>
	where
		Self: 'lease;
	type Job<'lease>
		= RecoveryJob<'lease>
	where
		Self: 'lease;

	fn job(&self) -> &Self::Job<'_> {
		self.0.job()
	}

	fn open_segment(&self, file: &Self::File) -> Result<Self::Segment<'_>, Self::EffectError> {
		self.0.open_first_segment_for_append(file)
	}

	fn synchronize_publication<'lease>(
		&'lease self,
		names: &LeaseInventory<'lease, Self>,
	) -> Result<(), Self::EffectError> {
		self.0.sync_publication(names)
	}
}

impl RecoveryStageLease for NativeLease<'_> {
	type Metadata = SourceObservation;
	type PublishError = PublishError;
	type Publisher<'lease>
		= HeldPublisher<'lease>
	where
		Self: 'lease;
	type ResumeDirectory<'lease>
		= HeldDirectory<'lease>
	where
		Self: 'lease;

	fn prepare_retry<'lease, 'inventory: 'lease>(
		&'lease self,
		names: &'lease LeaseInventory<'inventory, Self>,
		binding: CopyBinding,
	) -> Result<Self::Publisher<'lease>, Self::EffectError>
	where
		Self: 'inventory,
	{
		self.0
			.prepare_retained_stage(names, binding)
			.map(HeldPublisher)
	}

	fn reopen_stage<'lease, 'inventory: 'lease>(
		&'lease self,
		names: &'lease LeaseInventory<'inventory, Self>,
	) -> Result<Self::ResumeDirectory<'lease>, Self::EffectError>
	where
		Self: 'inventory,
	{
		self.0.reopen_stage_directory(names).map(HeldDirectory)
	}

	fn source_timestamp(observed: ObservedTimestamp) -> Result<SourceTimestamp, ReadError> {
		SourceTimestamp::new(observed.seconds(), observed.nanoseconds())
	}

	fn is_conflict(error: &PublishError) -> bool {
		matches!(error, PublishError::Conflict)
	}
}

pub(super) struct HeldPublisher<'lease>(RetainedStage<'lease>);

impl ExclusivePublication for HeldPublisher<'_> {
	type Error = PublishError;

	fn publish_no_clobber(
		self,
		authorization: PublishNoClobber,
	) -> Result<(), PublicationFailure<PublishError>> {
		self.0
			.publish_no_clobber(authorization)
			.map_err(|cause| match cause {
				PublishError::Conflict => PublicationFailure::Conflict(cause),
				_ => PublicationFailure::Uncertain(cause),
			})?;
		super::super::checkpoint(CopyCheckpoint::RetryRenamedAndSynced);
		Ok(())
	}
}

pub(super) struct HeldDirectory<'lease>(RecoveryStageDirectory<'lease>);

impl ResumeStageDirectory<SourceObservation, FileIdentity> for HeldDirectory<'_> {
	type Error = StageError;
	type PublicationError = PublishError;
	type Reader<'stage>
		= ClosedStage<'stage>
	where
		Self: 'stage;
	type Writer<'stage>
		= WriteStage<'stage>
	where
		Self: 'stage;

	fn identity(&self) -> LinuxFileIdentity {
		Self::record_identity(self.0.identity())
	}

	fn record_identity(identity: FileIdentity) -> LinuxFileIdentity {
		LinuxFileIdentity::new(identity.device(), identity.inode())
	}

	fn open_writer(&mut self, binding: CopyBinding) -> Result<Self::Writer<'_>, Self::Error> {
		self.0.open_writer(binding)
	}

	fn open_flushed_readback(
		&mut self,
		binding: CopyBinding,
		source: SourceObservation,
	) -> Result<Self::Reader<'_>, Self::Error> {
		self.0.open_flushed_readback(binding, source)
	}
}

impl ReceiptLease for NativeLease<'_> {
	type EffectError = StageError;
	type ExistingReceipt = RecoveryFile;
	type Directory<'lease>
		= HeldReceipts<'lease>
	where
		Self: 'lease;

	fn open_receipt_directory(&self) -> Result<Self::Directory<'_>, Self::EffectError> {
		self.0.open_receipt_directory().map(HeldReceipts)
	}

	fn sync_job_directory(&self) -> Result<(), Self::EffectError> {
		self.0.sync_job_directory()
	}
}

pub(super) struct HeldReceipts<'lease>(RecoveryReceiptDirectory<'lease>);

impl FinishReceiptDirectory for HeldReceipts<'_> {
	type Error = StageError;
	type ExistingReceipt = RecoveryFile;
	type Record = NativeReceiptRecord;

	fn sync_receipt(&self, receipt: &Self::ExistingReceipt) -> Result<(), Self::Error> {
		self.0.sync_receipt(receipt)
	}

	fn create_receipt(&self) -> Result<Self::Record, Self::Error> {
		self.0.create_receipt()
	}

	fn sync_directory(&self) -> Result<(), Self::Error> {
		self.0.sync_directory()
	}
}
