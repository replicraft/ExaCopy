use exacopy_endpoint::UnixComponent;
use exacopy_platform::linux::{DestinationRoot, PublishError, ReadError, ReadRoot, StageError};

use super::super::{CopyReceipt, LocalCopyPlan, PlanAttempt};
use super::{
	CopyError, CopyProfile, PlanningRoots, copy_with_capabilities, plan_with_capabilities,
};

/// The exact errors returned by native Linux copy and planning.
pub type LocalCopyError = CopyError<ReadError, StageError, PublishError>;

/// The independently authorized Linux roots and their caller-assigned IDs.
pub type CopyRoots<'root> = PlanningRoots<'root, ReadRoot, DestinationRoot>;

/// Observes one regular source and an absent target under the authorized roots.
///
/// The resulting plan binds the observations and names for this attempt. Planning may
/// update source access time through a bounded EOF probe. Applying the plan reopens the
/// source through the authorized root and checks the current observations again.
///
/// # Errors
/// Reports unsafe, unsupported, or occupied names and failures to observe the source.
pub fn plan_new_file<'name>(
	roots: CopyRoots<'_>,
	attempt: PlanAttempt<'name>,
	source: UnixComponent<'name>,
	target: UnixComponent<'name>,
) -> Result<LocalCopyPlan<'name>, LocalCopyError> {
	plan_with_capabilities(roots, attempt, source, target)
}

/// Executes the planned single-file Linux copy with independent verification and a receipt.
///
/// The authorized roots must still match the plan and the target must be absent. The
/// private owner, plan and journal record the operation. A synchronized intent precedes
/// the exclusive rename. The receipt is synchronized and then bound by a final journal
/// frame. Completed barrier calls do not qualify the filesystem for power-loss durability.
///
/// # Errors
/// Preserves the source, pre-existing target and any private job material on failure.
/// Once intent is written, a failure can require inventory of the actual namespace.
pub fn copy_new_file<'name>(
	roots: CopyRoots<'_>,
	plan: &LocalCopyPlan<'name>,
	profile: CopyProfile<'_>,
	scratch: &mut [u8],
) -> Result<CopyReceipt<'name>, LocalCopyError> {
	copy_with_capabilities(roots, plan, profile, scratch)
}
