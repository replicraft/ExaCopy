//! Links the Linux local copy entry points to the selected platform capabilities.

use exacopy_endpoint::UnixComponent;
use exacopy_platform::linux::{DestinationRoot, PublishError, ReadError, ReadRoot, StageError};
use exacopy_transfer::linux::{
	CopyError, CopyProfile, CopyReceipt, LocalCopyPlan, PlanAttempt, PlanningRoots,
	copy_with_capabilities, plan_with_capabilities,
};

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
	copy_with_capabilities(roots, plan, profile, scratch)
}
