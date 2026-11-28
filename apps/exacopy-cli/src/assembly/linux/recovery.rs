use exacopy_content::validate_stream_input;
use exacopy_endpoint::UnixComponent;
use exacopy_platform::linux::{DestinationRoot, PublishError, ReadError, ReadRoot, StageError};
use exacopy_transfer::linux::{
	FinishFailure, InspectionError, RecoveryInspection, RecoveryProfile, RecoveryStep,
	SourceRecoveryFailure, finish_with_lease, inspect_with_job, resume_with_lease,
	retry_with_lease,
};

mod lease;

use lease::NativeLease;

/// The native Linux errors from read-only job inspection.
pub type RecoveryInspectError = InspectionError<ReadError, StageError>;
/// The native Linux errors from finishing an existing publication.
pub type RecoveryFinishError = FinishFailure<ReadError, StageError>;
/// The native Linux errors from retrying or resuming under a source grant.
pub type RecoveryRetryError = SourceRecoveryFailure<ReadError, StageError, PublishError>;
/// A held native source root and its independently assigned grant.
pub type RecoverySource<'root> = exacopy_transfer::linux::RecoverySource<'root, ReadRoot>;

/// Inspects an authenticated job under a retained shared lease.
///
/// # Errors
/// Refuses unsafe or unauthenticated records and changed namespace observations.
pub fn inspect_recovery(
	destination: &DestinationRoot,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	scratch: &mut [u8],
) -> Result<RecoveryInspection, RecoveryInspectError> {
	validate_stream_input(0, scratch.len()).map_err(InspectionError::Input)?;
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
	inspect_with_job(&job, name, profile, scratch)
}

/// Completes the journal and receipt after an already-published copy.
///
/// # Errors
/// Fails when the exclusive lease, retained evidence, or durability cannot be confirmed.
pub fn finish_recovery(
	destination: &DestinationRoot,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	scratch: &mut [u8],
) -> Result<RecoveryInspection, RecoveryFinishError> {
	validate_stream_input(0, scratch.len()).map_err(InspectionError::Input)?;
	let lease = NativeLease::acquire(destination, name)?;
	finish_with_lease(&lease, name, profile, scratch)
}

/// Retries exclusive publication of a verified retained stage.
///
/// # Errors
/// Refuses conflicting or incomplete evidence and leaves uncertain effects for reconciliation.
pub fn retry_recovery(
	destination: &DestinationRoot,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	source: RecoverySource<'_>,
	scratch: &mut [u8],
) -> Result<RecoveryInspection, RecoveryRetryError> {
	validate_stream_input(0, scratch.len()).map_err(InspectionError::Input)?;
	let lease = NativeLease::acquire(destination, name)?;
	retry_with_lease(&lease, name, profile, source, scratch, super::checkpoint)
}

/// Resumes an interrupted copy from its authenticated private stage.
///
/// # Errors
/// Refuses changed scope or evidence and leaves partial writes in the original private stage.
pub fn resume_recovery(
	destination: &DestinationRoot,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	source: RecoverySource<'_>,
	scratch: &mut [u8],
) -> Result<RecoveryInspection, RecoveryRetryError> {
	validate_stream_input(0, scratch.len()).map_err(InspectionError::Input)?;
	let lease = NativeLease::acquire(destination, name)?;
	resume_with_lease(&lease, name, profile, source, scratch, super::checkpoint)
}
