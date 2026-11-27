//! Read-only native admission before opening another remote connection.

use exacopy_endpoint::UnixComponent;
use exacopy_journal::remote_download::RemoteEpochs;
use exacopy_journal::remote_download::finalization_replay::RemoteFinalizationReplay;
use exacopy_journal::remote_download::replay::MAX_REMOTE_REPLAY_ATTEMPTS;
use exacopy_platform::linux::RecoveryJob;

use super::lease::inspect_capture;
use super::{Error, ResumeCapacity, record_identity};

/// Checks the fixed bounds for spending a fresh allocation on this segment.
pub(super) fn check_capacity(
	attempts: usize,
	previous: Option<RemoteEpochs>,
) -> Result<(), ResumeCapacity> {
	if attempts >= MAX_REMOTE_REPLAY_ATTEMPTS {
		return Err(ResumeCapacity::AllocationsExhausted);
	}
	if previous.is_some_and(|epoch| {
		epoch.run.checked_add(1).is_none() || epoch.source.checked_add(1).is_none()
	}) {
		return Err(ResumeCapacity::EpochsExhausted);
	}
	Ok(())
}

/// Checks old authenticated attempt names and allocation capacity under startup custody.
///
/// The caller holds the shared read lease and has checked the exact owner, complete
/// ordinary history and physical EOF. These observations confer no write authority.
pub(crate) fn check_resume_startup(
	job: &RecoveryJob<'_>,
	target: UnixComponent<'_>,
	replay: &RemoteFinalizationReplay<'_>,
) -> Result<(), Error> {
	let attempts = replay.attempts();
	check_capacity(
		attempts.len(),
		attempts.last().map(|attempt| attempt.epochs()),
	)?;
	let directory = replay
		.stage_directory_prepared()
		.ok_or(Error::UnknownStage)?
		.directory();
	if attempts.is_empty()
		&& job.stage_directory_identity()?.map(record_identity) != Some(directory)
	{
		return Err(Error::UnknownStage);
	}
	for attempt in attempts {
		inspect_capture(job, attempt, target, directory)?;
	}
	job.recheck()?;
	Ok(())
}
