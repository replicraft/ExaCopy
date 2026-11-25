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
pub(crate) mod protected_snapshot;
mod publication_capabilities;
mod recovery;
mod recovery_capabilities;
mod source;
mod stage;
mod staging_capabilities;

pub use handle::FileIdentity;
pub use job::{
	CheckpointDirectory, JobDirectory, JournalDirectory, ReceiptDirectory, TargetStatus,
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
	ProcessCrashProfileId, observe_process_crash_environment,
};
pub use recovery::{
	FreshRecoveryStage, RecoveryFile, RecoveryInventory, RecoveryJob, RecoveryReadLease,
	RecoveryReceiptDirectory, RecoveryStageDirectory, RecoveryWriteLease, RetainedStage,
};
pub use source::{
	ExtendedAttributes, ReadError, ReadRoot, SourceFile, SourceObservation, SourceTimestamp,
};
pub use stage::{
	ClosedStage, DestinationRoot, DirectoryBarriersError, PublishError, StageDirectory, StageError,
	WriteStage,
};

pub use mount_observation::MountObservations;
