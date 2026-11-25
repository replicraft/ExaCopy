use exacopy_content::validate_stream_input;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{DurableJournal, SyncedFrame};
use exacopy_platform::linux::{DestinationRoot, RecoveryFile, RecoveryWriteLease};

use super::super::CopyReceipt;
use super::{RecoveryInspectError, RecoveryInspection, RecoveryProfile, RecoveryStep};

mod capabilities;
mod error;
mod native;
mod protocol;

pub use error::RecoveryFinishError;

/// Completes the journal and receipt after an already-published Linux copy.
///
/// The caller authorizes this specific job under the held destination and supplies its
/// independently trusted profile. Recovery obtains an exclusive job lease, verifies the
/// historical evidence and freshly checks the current published inode, then synchronizes
/// the relevant directories and completes the job's private history. Running this again
/// after receipt commitment returns the existing complete observation.
///
/// An intact private stage, a conflict, and a torn journal yield their current
/// inspection dispositions. This operation issues no new publication or deletion.
///
/// # Errors
/// Reports authentication, observation, effect recording, or barrier failures. Existing
/// source and destination names and all previously reached records remain in place.
pub fn finish_recovery(
	destination: &DestinationRoot,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	scratch: &mut [u8],
) -> Result<RecoveryInspection, RecoveryFinishError> {
	validate_stream_input(0, scratch.len()).map_err(super::RecoveryInspectError::Input)?;
	let lease = acquire_lease(destination, name)?;
	finish_leased(&lease, name, profile, scratch)
}

pub(super) fn acquire_lease<'root>(
	destination: &'root DestinationRoot,
	name: UnixComponent<'_>,
) -> Result<RecoveryWriteLease<'root>, RecoveryInspectError> {
	let previous = destination
		.open_recovery_job(name)
		.map_err(RecoveryStep::Job.platform())?;
	destination
		.try_recovery_write_lease(name, previous.identity())
		.map_err(RecoveryStep::Lease.platform())
}

pub(super) fn finish_leased(
	lease: &RecoveryWriteLease<'_>,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	scratch: &mut [u8],
) -> Result<RecoveryInspection, RecoveryFinishError> {
	protocol::finish(lease, name, profile, scratch).map_err(RecoveryFinishError::from)
}

pub(super) fn sync_receipt(
	lease: &RecoveryWriteLease<'_>,
	receipt: &CopyReceipt<'_>,
	existing: Option<&RecoveryFile>,
) -> Result<(), RecoveryFinishError> {
	protocol::sync_receipt(lease, receipt, existing).map_err(RecoveryFinishError::from)
}

pub(super) fn required<T>(value: Option<T>) -> Result<T, RecoveryFinishError> {
	value.ok_or(RecoveryFinishError::IncompleteEvidence)
}

pub(super) fn append(
	journal: &mut DurableJournal,
	kind: FrameKind,
	payload: &[u8],
) -> Result<SyncedFrame, RecoveryFinishError> {
	journal
		.append(kind, payload)
		.map_err(|source| RecoveryFinishError::Journal { kind, source })
}

pub(super) fn completion(
	step: RecoveryStep,
) -> impl FnOnce(exacopy_platform::linux::StageError) -> RecoveryFinishError {
	move |source| RecoveryFinishError::Completion(step.platform()(source))
}
