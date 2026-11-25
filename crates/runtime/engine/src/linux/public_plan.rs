use exacopy_endpoint::linux_copy::CopyDestinationView;
use exacopy_platform::linux::{FileIdentity, ReadError, ReadRoot, StageError};
use exacopy_transfer::copy_planning::{
	CreateNewRequest, PlannedCopy, PlanningError, plan_create_new,
};

use super::NamedReadView;

/// Read-only planning failure at the native Linux application boundary.
pub type NativePlanningError = PlanningError<ReadError, StageError>;

/// Plans one public preserve-copy entry from an explicit named source and target observation.
///
/// The supplied roots remain independently authorized by the caller. This
/// entry point only has read access to the source and name observation for
/// the target.
///
/// # Errors
/// Fails if either observation, source policy, or public encoding is refused.
pub fn plan_public_new_file(
	source: &ReadRoot,
	destination: &dyn CopyDestinationView<Error = StageError>,
	request: CreateNewRequest<'_>,
	allow_source: impl FnOnce(FileIdentity) -> bool,
	scratch: &mut [u8],
) -> Result<PlannedCopy, NativePlanningError> {
	if request.source.root_id == request.destination.root_id
		&& destination.identity() != source.identity().into()
	{
		return Err(PlanningError::InvalidIdentity);
	}
	plan_create_new(
		request,
		|name| NamedReadView::open(source, name),
		allow_source,
		destination,
		scratch,
	)
}
