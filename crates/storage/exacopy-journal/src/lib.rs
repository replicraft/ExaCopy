//! Bounded, versioned journal framing and chain checks for local recovery.

#![forbid(unsafe_code)]

mod darwin_phases;
mod darwin_prepared;
mod durable;
pub mod frame;
mod intent;
pub mod managed_action_prepared;
pub mod managed_activation_claim;
mod owner;
mod prepared;
mod publication_records;
mod recovery_records;
pub mod remote_download;
mod verification_records;
pub mod windows_bootstrap;
pub mod windows_capture;

pub use darwin_phases::{
	DarwinDurabilityRecorded, DarwinMetadataRecorded, DarwinNamespaceObservation,
	DarwinPhaseBinding, DarwinPhaseDigest, DarwinPhaseError, DarwinPublicationBarriers,
	DarwinPublicationNames, DarwinPublicationOutcome, DarwinPublishIntent, DarwinPublishObserved,
	DarwinPublishTarget, DarwinPublishedRecoveryEvidence, DarwinReceiptCommitted,
	DarwinReceiptDigest, DarwinRecoveryDecision, DarwinRecoveryDecisionFrames,
	DarwinRecoveryHistory, DarwinRecoveryStarted, DarwinRequiredMetadata, DarwinStageSealed,
	DarwinStreamEvidence, DarwinVerificationRecorded,
};
pub use darwin_prepared::{
	DarwinEntryPreparation, DarwinEntryPrepared, DarwinJobPrepared, DarwinPreparedError,
	DarwinRootBinding, DarwinSourceMetadata, DarwinSourceTimes, DarwinSourceView, DarwinStageId,
	DarwinStageObservation,
};
pub use durable::{DurableJournal, DurableJournalError, MAX_FIRST_SEGMENT_BYTES, SyncedFrame};
pub use exacopy_endpoint::JournalFileBarrier;
pub use intent::{
	ApplyCrashProfile, ApplyIntentEvidence, ApplyProcessCrashEnvironment, ApplyQualification,
	ApplyQualificationDigest, IntentError, JournalEntryId, JournalEpoch, JournalJobId,
	LinuxFileIdentity, MAX_PUBLIC_APPLY_INTENT_BYTES, PlanDigest, PublicApplyAssociation,
	PublicApplyIntent, PublicApplyIntentError, PublicationPrimitive, PublishIntent,
	PublishIntentContext, PublishIntentTarget, VerificationDigest,
};
pub use owner::{
	ApplyMetadataPolicyDigest, ApplyRequestedDurability, ApprovedPublicPlanDigest,
	ApprovedStreamDigest, DarwinFileIdentity, DarwinOwnerManifest, DarwinOwnerRecord,
	DarwinVolumeIdentity, MAX_OWNER_BYTES, OwnerDigest, OwnerError, OwnerManifest, OwnerProfileId,
	OwnerRecord, OwnerStateDirectory, OwnerTimestamp, OwnerToken, PublicApplyBinding,
	PublicApplyOwnerManifest, PublicApplyOwnerRecord, PublicPlanEntryId,
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
