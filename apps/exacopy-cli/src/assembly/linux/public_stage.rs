use exacopy_endpoint::UnixComponent;
use exacopy_platform::linux::DestinationRoot;
use exacopy_transfer::linux::{
	InspectionError, PublicStageInspection, RecoveryProfile, RecoveryStep,
	inspect_public_stage_with_job,
};
#[cfg(test)]
use exacopy_transfer::linux::{PublicApplyStage, PublicApplyStageRequest, stage_public_apply};

use super::RecoveryInspectError;
#[cfg(test)]
use super::{CopyRoots, LocalCopyError};

mod checked;
mod grant;
#[cfg(kani)]
pub(crate) use grant::phase_proof;
#[cfg(any(test, feature = "experimental-linux-public-apply"))]
mod qualification;
mod reconcile;
#[cfg(feature = "experimental-linux-public-apply")]
pub use checked::{AppliedPublicPlanError, LiveQualificationError, apply_qualified_public_plan};
#[cfg(feature = "experimental-linux-public-apply")]
pub use grant::{
	LocalApplyGrant, LocalApplyGrantError, LocalApplyHostSelection, LocalApplyIssuer,
	LocalApplyRootSelection,
};
#[cfg(feature = "experimental-linux-public-apply")]
pub use qualification::{
	LocalApplyQualificationEnrollment, QualifiedPublicApplyProposalError,
	stage_qualified_public_apply,
};
#[cfg(feature = "experimental-linux-public-apply")]
pub use reconcile::reconcile_public_apply;

#[cfg(test)]
mod tests;

#[cfg(test)]
fn stage(
	roots: CopyRoots<'_>,
	request: PublicApplyStageRequest<'_, '_, '_>,
	scratch: &mut [u8],
) -> Result<PublicApplyStage, LocalCopyError> {
	stage_public_apply(roots, request, scratch, |_| {})
}

pub(crate) fn inspect(
	destination: &DestinationRoot,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	scratch: &mut [u8],
) -> Result<PublicStageInspection, RecoveryInspectError> {
	let job = destination
		.open_recovery_job(name)
		.map_err(|source| InspectionError::Platform {
			step: RecoveryStep::Job,
			source,
		})?;
	let _lease = job
		.try_read_lease()
		.map_err(|source| InspectionError::Platform {
			step: RecoveryStep::Lease,
			source,
		})?;
	inspect_public_stage_with_job(&job, name, profile, scratch)
}
