//! Linux handle-relative source, staging, and exclusive publication primitives.

mod handle;
mod job;
mod recovery;
mod source;
mod stage;
mod staging_capabilities;

pub use handle::FileIdentity;
pub use job::{
	CheckpointDirectory, JobDirectory, JournalDirectory, ReceiptDirectory, TargetStatus,
};
pub use recovery::{
	RecoveryFile, RecoveryInventory, RecoveryJob, RecoveryReadLease, RecoveryReceiptDirectory,
	RecoveryStageDirectory, RecoveryWriteLease, RetainedStage,
};
pub use source::{
	ExtendedAttributes, ReadError, ReadRoot, SourceFile, SourceObservation, SourceTimestamp,
};
pub use stage::{
	ClosedStage, DestinationRoot, DirectoryBarriersError, PublishError, StageDirectory, StageError,
	WriteStage,
};
