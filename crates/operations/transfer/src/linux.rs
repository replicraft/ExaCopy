//! Linux local transfer policy, bounded records, and recovery orchestration.

mod checkpoint;
mod job;
mod local_copy;
mod plan;
mod receipt;
mod recovery;
mod replay;

pub use checkpoint::CopyCheckpoint;
pub use job::{BootstrapError, JobBootstrap, JobStep, PreparedJob};
pub use local_copy::{
	CopyError, CopyProfile, PlanningRoots, PublicApplyStage, PublicApplyStageRequest,
	copy_with_capabilities, plan_with_capabilities, stage_public_apply,
};
pub use plan::{
	DestinationPlanBinding, LocalCopyPlan, LocalCopyPlanError, MAX_LOCAL_COPY_PLAN_BYTES,
	PlanAttempt, SourcePlanBinding,
};
pub use receipt::{CopyReceipt, MAX_COPY_RECEIPT_BYTES, ReceiptError, ReceiptEvidence};
pub use recovery::{
	FinishFailure, FinishReceiptDirectory, InspectionError, LeaseInventory, LeaseReadError,
	ReceiptLease, RecoveryDisposition, RecoveryInspection, RecoveryIssue, RecoveryLease,
	RecoveryProfile, RecoverySource, RecoveryStageLease, RecoveryStep, ResumeStageDirectory,
	SourceRecoveryFailure, SourceRecoveryResult, finish_with_lease, inspect_with_job,
	resume_with_lease, retry_with_lease,
};
pub use replay::{
	JournalBoundary, JournalReplay, JournalReplayError, JournalTail, MAX_LOCAL_JOURNAL_BYTES,
	replay_journal,
};

pub use crate::linux_staging::StageRequest;
use crate::linux_staging::{check_source, observe};
