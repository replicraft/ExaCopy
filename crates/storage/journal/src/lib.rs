//! Bounded, versioned journal framing and chain checks for local recovery.

#![forbid(unsafe_code)]

mod durable;
pub mod frame;
mod intent;
mod owner;
mod prepared;
mod publication_records;
mod recovery_records;
mod verification_records;

pub use durable::{DurableJournal, DurableJournalError, SyncedFrame};
pub use intent::{
	IntentError, JournalEntryId, JournalEpoch, JournalJobId, LinuxFileIdentity, PlanDigest,
	PublicationPrimitive, PublishIntent, PublishIntentContext, PublishIntentTarget,
	VerificationDigest,
};
pub use owner::{
	DarwinFileIdentity, DarwinOwnerManifest, DarwinOwnerRecord, DarwinVolumeIdentity,
	MAX_OWNER_BYTES, OwnerDigest, OwnerError, OwnerManifest, OwnerProfileId, OwnerRecord,
	OwnerStateDirectory, OwnerTimestamp, OwnerToken,
};
pub use prepared::{
	DestinationRootBinding, EntryPreparation, EntryPrepared, JobPrepared, JournalContext,
	LiveSourceView, ObservedTimestamp, PreparedError, PreparedTarget, RootCapabilityId,
	SourceInodeMetadata, SourceTimes, TargetObservation,
};
pub use publication_records::{
	DurabilityRecorded, LOCAL_RECEIPT_LOCATION, LinuxPublicationBarriers, NamespaceObservation,
	PublicationOutcome, PublicationRecordError, PublishObserved, ReceiptCommitted, ReceiptDigest,
};
pub use recovery_records::{
	PublishedRecoveryEvidence, RangeResumeEvidence, RangeResumeStarted, RecoveryDecision,
	RecoveryDecisionFrames, RecoveryDirectories, RecoveryRecordError, RecoveryStartEvidence,
	RecoveryStarted, RetainedPublicationDecision, RetainedPublicationEvidence,
};
pub use verification_records::{
	BasicMetadata, MAX_CHECKPOINT_RANGE_BYTES, MAX_RANGE_CHECKPOINTS, MAX_RANGE_PAGE_BYTES,
	MetadataOmission, MetadataRecorded, RangeCheckpoint, RangePage, RangePageRef,
	SourceMeasurementId, StageSealed, StreamDigest, StreamEvidence, StreamLength,
	VerificationRecordError, VerificationRecorded,
};
