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
