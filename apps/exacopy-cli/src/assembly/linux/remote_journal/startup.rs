//! Read-only native admission before opening another remote connection.

use exacopy_endpoint::UnixComponent;
use exacopy_journal::remote_download::RemoteEpochs;
use exacopy_journal::remote_download::finalization_replay::RemoteFinalizationReplay;
use exacopy_journal::remote_download::replay::{MAX_REMOTE_REPLAY_ATTEMPTS, RemoteReplayBoundary};
use exacopy_platform::linux::{RecoveryFile, RecoveryJob, RecoveryReadLease};

use super::lease::{check_record, inspect_capture};
use super::{Error, ResumeCapacity, record_identity};

#[cfg(feature = "experimental-verified-prefix-resume")]
mod witnessed;

#[cfg(feature = "experimental-verified-prefix-resume")]
pub(crate) use witnessed::CheckedOriginalWitnessStartup;

/// The exact ordinary replay selected under the shared startup lease.
pub(crate) struct CheckedResumeStartup<'held> {
	lease: RecoveryReadLease<'held>,
	history: ResumeHistory<'held>,
}

impl<'held> CheckedResumeStartup<'held> {
	pub(crate) fn new(
		lease: RecoveryReadLease<'held>,
		owner: RecoveryFile,
		segment: RecoveryFile,
		boundary: RemoteReplayBoundary,
	) -> Self {
		let job = lease.job();
		Self {
			lease,
			history: ResumeHistory {
				job,
				owner,
				segment,
				boundary,
			},
		}
	}

	pub(super) fn release_for_exclusive(self) -> ResumeHistory<'held> {
		let Self { lease, history } = self;
		// Release only the cooperative lock. Retain the exact three native
		// objects until the exclusive admission has checked the same history.
		drop(lease);
		history
	}
}

pub(super) struct ResumeHistory<'held> {
	job: &'held RecoveryJob<'held>,
	owner: RecoveryFile,
	segment: RecoveryFile,
	boundary: RemoteReplayBoundary,
}

impl ResumeHistory<'_> {
	pub(super) fn check_job(&self, reopened: &RecoveryJob<'_>) -> Result<(), Error> {
		if self.job.identity() != reopened.identity()
			|| self.job.destination_identity() != reopened.destination_identity()
		{
			return Err(Error::Binding);
		}
		self.job.recheck()?;
		Ok(())
	}

	pub(super) fn check_owner(&self, reopened: &RecoveryFile) -> Result<(), Error> {
		check_record(&self.owner, reopened)
	}

	pub(super) fn check_segment(&self, reopened: &RecoveryFile) -> Result<(), Error> {
		if reopened.len() != self.boundary.offset {
			return Err(Error::Binding);
		}
		check_record(&self.segment, reopened)
	}

	pub(super) const fn boundary(&self) -> RemoteReplayBoundary {
		self.boundary
	}
}

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
