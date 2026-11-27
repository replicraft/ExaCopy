//! Composes Linux local operation entry points with the selected platform capabilities.

use exacopy_endpoint::UnixComponent;
use exacopy_platform::linux::{
	ClosedStage, DestinationRoot, JobDirectory, PublishError, ReadError, ReadRoot, SourceFile,
	StageDirectory, StageError,
};
use exacopy_transfer::linux::{
	BootstrapError, CopyCheckpoint, CopyError, CopyProfile, CopyReceipt, LocalCopyPlan,
	PlanAttempt, PlanningRoots, StageRequest, copy_with_capabilities, plan_with_capabilities,
};

#[cfg(test)]
mod crash_tests;
#[cfg(feature = "experimental-linux-managed-sync")]
pub mod managed_sync;
mod public_plan;
#[cfg(any(test, feature = "experimental-linux-public-apply"))]
pub(crate) mod public_stage;
mod recovery;
#[cfg(all(test, feature = "experimental-ssh-capture"))]
#[expect(
	dead_code,
	reason = "private application handoff has no live qualification or command dispatch"
)]
mod remote_continued;
#[cfg(feature = "experimental-ssh-capture")]
pub mod remote_download;
#[cfg(feature = "experimental-ssh-capture")]
mod remote_journal;
#[cfg(feature = "experimental-ssh-capture")]
mod remote_stage;
#[cfg(all(test, feature = "experimental-ssh-capture"))]
mod remote_witness_authority;

pub use public_plan::{NativePlanningError, plan_public_new_file};

pub use recovery::{
	RecoveryFinishError, RecoveryInspectError, RecoveryRetryError, RecoverySource, finish_recovery,
	inspect_recovery, resume_recovery, retry_recovery,
};

pub use exacopy_transfer::linux::{
	RecoveryDisposition, RecoveryInspection, RecoveryIssue, RecoveryProfile,
};

/// Native Linux stage errors reported at the last established model phase.
pub type StageCopyError = exacopy_transfer::linux_staging::StageCopyError<ReadError, StageError>;
/// Native Linux staging failures retaining the adapter cause.
pub type StageFailure = exacopy_transfer::linux_staging::StageFailure<ReadError, StageError>;
/// A native private stage independently verified and reopened without write authority.
pub type VerifiedStage<'stage> =
	exacopy_transfer::linux_staging::VerifiedStage<ClosedStage<'stage>>;
/// A private Linux job pinned to the held destination.
pub type PreparedJob<'root> = exacopy_transfer::linux::PreparedJob<JobDirectory<'root>>;
/// The exact namespace or evidence failure from native Linux job bootstrap.
pub type JobBootstrapError = BootstrapError<StageError>;

/// Copies into a private Linux stage and independently verifies its content and metadata.
///
/// # Errors
/// Reports the phase and exact failure. Any allocated stage remains private.
pub fn stage_verified<'stage>(
	source: &SourceFile,
	directory: &'stage StageDirectory<'_>,
	request: StageRequest<'_>,
	scratch: &mut [u8],
) -> Result<VerifiedStage<'stage>, StageCopyError> {
	exacopy_transfer::linux_staging::stage_verified(source, directory, request, scratch, None)
}

/// The independently authorized Linux roots and their caller-assigned IDs.
pub type CopyRoots<'root> = PlanningRoots<'root, ReadRoot, DestinationRoot>;

/// The typed failures produced by composing these native capabilities.
pub type LocalCopyError = CopyError<ReadError, StageError, PublishError>;

/// Plans a preserve-mode copy using the selected Linux roots.
/// # Errors
/// Reports failures of native observations or transfer-policy admission.
pub fn plan_new_file<'name>(
	roots: CopyRoots<'_>,
	attempt: PlanAttempt<'name>,
	source: UnixComponent<'name>,
	target: UnixComponent<'name>,
) -> Result<LocalCopyPlan<'name>, LocalCopyError> {
	plan_with_capabilities(roots, attempt, source, target)
}

/// Runs a preserve-mode copy using the selected Linux roots.
/// # Errors
/// Reports the rejected or failed step. Retained evidence may require reconciliation.
pub fn copy_new_file<'name>(
	roots: CopyRoots<'_>,
	plan: &LocalCopyPlan<'name>,
	profile: CopyProfile<'_>,
	scratch: &mut [u8],
) -> Result<CopyReceipt<'name>, LocalCopyError> {
	copy_with_capabilities(roots, plan, profile, scratch, checkpoint)
}

fn checkpoint(boundary: CopyCheckpoint) {
	#[cfg(test)]
	match boundary {
		CopyCheckpoint::RangePageSynced | CopyCheckpoint::RangeFrameSynced => {
			crash_tests::pause_range_at(boundary);
		}
		CopyCheckpoint::CopyMetadataApplied | CopyCheckpoint::RangeResumeMetadataApplied => {
			crash_tests::pause_metadata_at(boundary);
		}
		_ => crash_tests::pause_at(boundary),
	}
	#[cfg(not(test))]
	let _ = boundary;
}
