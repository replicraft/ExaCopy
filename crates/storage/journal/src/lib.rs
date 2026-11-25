//! Bounded, versioned journal framing and chain checks for local recovery.

#![forbid(unsafe_code)]

mod durable;
pub mod frame;
mod intent;
mod owner;
mod prepared;
mod verification_records;

pub use durable::{DurableJournal, DurableJournalError, SyncedFrame};
pub use intent::{
	IntentError, JournalEntryId, JournalEpoch, JournalJobId, LinuxFileIdentity, PlanDigest,
	PublicationPrimitive, PublishIntent, PublishIntentContext, PublishIntentTarget,
	VerificationDigest,
};
pub use owner::{
	MAX_OWNER_BYTES, OwnerDigest, OwnerError, OwnerManifest, OwnerProfileId, OwnerRecord,
	OwnerStateDirectory, OwnerTimestamp, OwnerToken,
};
pub use prepared::{
	DestinationRootBinding, EntryPreparation, EntryPrepared, JobPrepared, JournalContext,
	LiveSourceView, ObservedTimestamp, PreparedError, PreparedTarget, RootCapabilityId,
	SourceInodeMetadata, SourceTimes, TargetObservation,
};
pub use verification_records::{
	BasicMetadata, MetadataOmission, MetadataRecorded, StageSealed, StreamDigest, StreamEvidence,
	StreamLength, VerificationRecordError, VerificationRecorded,
};
