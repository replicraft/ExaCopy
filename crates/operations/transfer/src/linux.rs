//! Sequential Linux staging and independent read-back verification.

use exacopy_content::ContentDigest;
use exacopy_model::{CopyPhase, CopySession};
use exacopy_platform::linux::{ClosedStage, FileIdentity, SourceFile, StageDirectory};

use crate::linux_staging;

mod error;
mod job;
mod local_copy;
mod plan;
mod receipt;
mod recovery;
mod replay;

pub use error::{StageCopyError, StageFailure};
pub use job::{BootstrapError, JobBootstrap, JobBootstrapError, JobStep, PreparedJob};
pub use local_copy::{
	CopyError, CopyProfile, CopyRoots, LocalCopyError, PlanningRoots, copy_new_file,
	copy_with_capabilities, plan_new_file, plan_with_capabilities,
};
pub use plan::{
	DestinationPlanBinding, LocalCopyPlan, LocalCopyPlanError, MAX_LOCAL_COPY_PLAN_BYTES,
	PlanAttempt, SourcePlanBinding,
};
pub use receipt::{CopyReceipt, MAX_COPY_RECEIPT_BYTES, ReceiptError, ReceiptEvidence};
pub use recovery::{
	RecoveryDisposition, RecoveryFinishError, RecoveryInspectError, RecoveryInspection,
	RecoveryIssue, RecoveryProfile, RecoveryRetryError, RecoverySource, RecoveryStep,
	finish_recovery, inspect_recovery, resume_recovery, retry_recovery,
};
pub use replay::{
	JournalBoundary, JournalReplay, JournalReplayError, JournalTail, MAX_LOCAL_JOURNAL_BYTES,
	replay_journal,
};

pub use crate::linux_staging::StageRequest;
use crate::linux_staging::{check_source, observe};

/// A private stage with independent source-stream and destination read-back agreement.
///
/// This type retains the pinned read-only handle and model session. Publication needs
/// separately recorded intent and recovery evidence.
#[derive(Debug)]
pub struct VerifiedStage<'stage> {
	stage: ClosedStage<'stage>,
	session: CopySession,
	digest: ContentDigest,
}

impl VerifiedStage<'_> {
	/// The verified BLAKE3 digest of the observed logical stream.
	#[must_use]
	pub const fn digest(&self) -> ContentDigest {
		self.digest
	}

	/// The verified logical length.
	#[must_use]
	pub fn length(&self) -> u64 {
		self.stage.length()
	}

	/// Compares the physical stage identity while this pinned handle remains held.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.stage.identity()
	}

	/// The model phase backed by observations made during this attempt.
	#[must_use]
	pub const fn phase(&self) -> CopyPhase {
		self.session.phase()
	}
}

/// Copies one observed Linux source stream into a new, private, independently verified stage.
///
/// The caller retains root authority and a unique attempt binding. The same bounded buffer
/// is used first for sequential copying and later for read-back, after writer release.
/// This path accepts the baseline native metadata subset. The source is live observed, and
/// independent read-back can be served by the OS cache.
///
/// # Errors
/// The current model phase and cause identify failure. An allocated stage remains private
/// for inspection. No target creation or deletion occurs during this operation.
pub fn stage_verified<'stage>(
	source: &SourceFile,
	directory: &'stage StageDirectory<'_>,
	request: StageRequest<'_>,
	scratch: &mut [u8],
) -> Result<VerifiedStage<'stage>, StageCopyError> {
	let (stage, session, digest) =
		linux_staging::stage_verified(source, directory, request, scratch, None)?.into_parts();
	Ok(VerifiedStage {
		stage,
		session,
		digest,
	})
}
