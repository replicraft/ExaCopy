//! Sequential Linux staging and independent read-back verification.

use exacopy_content::ContentDigest;
use exacopy_model::{CopyPhase, CopySession};
use exacopy_platform::linux::{ClosedStage, FileIdentity, SourceFile, StageDirectory};

use crate::linux_staging::{self, StageRecords as StageRecordSink};

mod error;
mod job;
mod local_copy;
mod plan;
mod receipt;
mod recovery;
mod replay;

pub use error::{StageCopyError, StageFailure};
pub use job::{JobBootstrap, JobBootstrapError, JobStep, PreparedJob};
use local_copy::checkpoints::StageRecords;
pub use local_copy::{CopyProfile, CopyRoots, LocalCopyError, copy_new_file, plan_new_file};
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
use crate::linux_staging::{
	begin_stage_reads, check_source, complete_stage_metadata, flush_written_stage, observe,
	verify_stage_readback,
};

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
	stage_with_preparation(source, directory, request, scratch, None)
}

fn stage_with_preparation<'stage>(
	source: &SourceFile,
	directory: &'stage StageDirectory<'_>,
	request: StageRequest<'_>,
	scratch: &mut [u8],
	records: Option<StageRecords<'_, '_>>,
) -> Result<VerifiedStage<'stage>, StageCopyError> {
	let mut records = records;
	let records = records
		.as_mut()
		.map(|records| records as &mut dyn StageRecordSink<_, _, _>);
	let (stage, session, digest) =
		linux_staging::stage_verified(source, directory, request, scratch, records)?.into_parts();
	#[cfg(test)]
	local_copy::crash_tests::pause_metadata_at(
		local_copy::crash_tests::Checkpoint::CopyMetadataApplied,
	);
	Ok(VerifiedStage {
		stage,
		session,
		digest,
	})
}
