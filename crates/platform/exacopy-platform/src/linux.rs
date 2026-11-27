//! Linux handle-relative source, staging, and exclusive publication primitives.

mod copy_capabilities;
mod handle;
mod job;
mod journal_segment;
mod mount_observation;
mod named_read;
mod owner_seed;
mod plan_bundle;
mod process_crash;
pub mod protected_slot;
pub(crate) mod protected_snapshot;
mod publication_capabilities;
mod recovery;
mod recovery_capabilities;
mod running_image;
mod source;
mod stage;
mod staging_capabilities;
mod sync_preview;
#[cfg(feature = "experimental-linux-managed-sync")]
mod sync_profile_store;

pub use handle::FileIdentity;
pub use job::{
	CheckpointDirectory, JobDirectory, JobDirectoryCreationError, JournalDirectory,
	ReceiptDirectory, TargetStatus,
};
pub use journal_segment::LinuxJournalSegment;
pub use named_read::NamedReadView;
pub use owner_seed::{
	HeldOwnerSeed, OWNER_SEED_BYTES, OwnerSeedError, initialize_owner_seed, kernel_random,
};
pub use plan_bundle::{
	LinuxPlanBundle, PlanBundleError, PlanBundlePages, PlanBundleRecord, PlanInputDirectory,
	PlanSeedError, PlanSeedStamp,
};
pub use process_crash::{
	ProcessCrashEligibility, ProcessCrashEnvironment, ProcessCrashProfileError,
	ProcessCrashProfileId, RemoteDestinationEligibility, RemoteDestinationEligibilityError,
	observe_process_crash_environment, observe_remote_destination,
};
pub use recovery::{
	ActiveWitnessReservation, ContinuationReservationError, FreshRecoveryStage,
	PendingProtectedWitness, PendingWitnessReservation, ProtectedWitnessEffect,
	ProtectedWitnessError, RecoveryFile, RecoveryInventory, RecoveryJob, RecoveryReadLease,
	RecoveryReceiptDirectory, RecoveryStageAnchor, RecoveryStageDirectory, RecoveryWriteLease,
	ReservedContinuationRequest, ReservedJournalRead, RetainedPrefixRead, RetainedPrefixSelection,
	RetainedStage, RetainedSuffixReadback, RetainedSuffixWriter, SealedProtectedWitness,
	SuffixEffect, SuffixError, SyncedRetainedPrefix, SyncedSuffixRange, WitnessCredentialLane,
	WitnessDurabilityAppend, WitnessDurabilityEffect, WitnessDurabilityError,
	WitnessDurabilityRequest, WitnessLinkCandidate, WitnessObservationAppend,
	WitnessPrepublicationAppend, WitnessPrepublicationPhase, WitnessPublication,
	WitnessPublicationError, WitnessPublicationName, WitnessPublicationNames,
	WitnessPublicationObservation, WitnessPublicationRequest, WitnessReceiptAppend,
	WitnessReceiptEffect, WitnessReceiptError, WitnessReceiptIdentity, WitnessReceiptNames,
	WitnessReceiptPlacement, WitnessReceiptPlan, WitnessReceiptRequest,
	WitnessReservationAuthority, WitnessReservationEffect, WitnessReservationError,
	WitnessReservationGateRequest, WitnessReservationObservationError, WitnessReservationPlan,
	WitnessedPublishedArtifacts, WitnessedPublishedSelection, WitnessedSuffixReadback,
	WitnessedTerminalArtifacts, WitnessedTerminalJournal, WitnessedTerminalSegment,
	WitnessedTerminalSelection,
};
pub use running_image::RunningExecutable;
pub use source::{
	ExtendedAttributes, ReadError, ReadRoot, SourceFile, SourceObservation, SourceTimestamp,
};
pub use stage::{
	ClosedStage, DestinationRoot, DirectoryBarriersError, PublishError, SelectedStreamGateRequest,
	SelectedStreamLocation, SelectedStreamMetadataReady, SelectedStreamNames,
	SelectedStreamObservation, SelectedStreamPublication, SelectedStreamPublicationAuthority,
	SelectedStreamPublishError, StageDirectory, StageError, WriteStage,
};

pub use mount_observation::MountObservations;

#[cfg(feature = "experimental-linux-managed-sync")]
pub use sync_profile_store::{
	SyncGenesisEffect, SyncGenesisEffectRequest, SyncGenesisIntent, SyncGenesisMember,
	SyncGenesisMemberBinding, SyncGenesisNativeIdentity, SyncGenesisOperation, SyncGenesisOutput,
	SyncGenesisPublishError, SyncGenesisPublishRequest, SyncGenesisPublished, SyncProfileHistory,
	SyncProfileSeed, SyncProfileStore, SyncProfileStoreError, SyncProfileStoreRecord,
};

pub use sync_preview::{
	SyncHistoryDirectory, SyncHistoryLocation, SyncHistoryReader, SyncPreviewEntry,
	SyncPreviewError, SyncPreviewPair, SyncPreviewRoots, SyncPreviewSelection,
};

#[cfg(feature = "experimental-linux-managed-sync")]
pub use sync_preview::{
	ManagedSyncError, ManagedSyncExpectedObject, ManagedSyncExpectedRoot, ManagedSyncNativeScope,
	ManagedSyncPreviewPair, ManagedSyncReadLease,
};
