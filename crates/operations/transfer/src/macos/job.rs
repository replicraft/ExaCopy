//! Synchronized preparation of owner-private managed APFS jobs.

use std::fmt;

use ed25519_dalek::SigningKey;
use exacopy_journal::{
	DarwinJobPrepared, DarwinOwnerRecord, DarwinRootBinding, DurableJournal, OwnerError,
	OwnerProfileId, OwnerTimestamp, OwnerToken, RootCapabilityId, SyncedFrame,
};
use exacopy_platform::macos::ManagedRegularFile;
use exacopy_platform::macos::staging::StageDirectory;
use exacopy_platform::macos::staging::jobs::{JobDirectory, JobName, JournalDirectory};

use super::plan::DarwinCopyPlan;

mod admission;
mod bootstrap;
mod entry;
mod error;

#[cfg(test)]
mod tests;

pub use entry::{
	DarwinCopyError, DarwinCopyFailure, EntryPreparationError, EntryPreparationFailure,
	PreparedDarwinEntry, PublicationProgress,
};
pub use error::{JobAdmissionError, JobBootstrapError, JobPreparationError, JobPreparationStep};

pub(super) use self::admission::native_identity;
use self::admission::{admit_destination, check_source};
use self::bootstrap::{JobPreparation, prepare_created_job};

#[cfg(test)]
use exacopy_journal::{JournalFileBarrier, frame::FrameKind};

pub(super) const STAGE_PAYLOAD: &[u8] = b"payload";

/// The independently trusted local signing profile and this attempt's owner claims.
#[derive(Clone, Copy)]
pub struct DarwinJobProfile<'profile> {
	/// Profile ID selected from trusted local configuration.
	pub id: OwnerProfileId,
	/// The key selected from the same trusted configuration as the profile ID.
	pub signer: &'profile SigningKey,
	/// The creation timestamp chosen by the coordinator.
	pub created: OwnerTimestamp,
	/// A fresh cryptographically random token independent of the job and profile IDs.
	pub owner_token: OwnerToken,
}

impl fmt::Debug for DarwinJobProfile<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("DarwinJobProfile")
			.finish_non_exhaustive()
	}
}

/// Held capabilities and independently selected IDs authorizing bootstrap for a plan.
#[derive(Debug, Clone, Copy)]
pub struct JobBootstrap<'held, 'profile> {
	/// The authorized source with the original pre-read observation.
	pub source: &'held ManagedRegularFile<'held>,
	/// The capability ID obtained independently of the plan for the held source root.
	pub source_root_id: RootCapabilityId,
	/// The reserved private child borrowing the authorized destination lease.
	pub container: &'held StageDirectory<'held>,
	/// The capability ID obtained independently of the plan for the container's held parent.
	pub destination_root_id: RootCapabilityId,
	/// The local profile independently selected for the request.
	pub profile: DarwinJobProfile<'profile>,
}

/// The exact owner and synced preparation evidence with the two directory leases held.
#[derive(Debug)]
pub struct PreparedDarwinJob<'job> {
	// The writer closes before the journal directory lease is released.
	journal: DurableJournal,
	_journal_directory: JournalDirectory<'job>,
	job: &'job JobDirectory<'job>,
	owner: DarwinOwnerRecord,
	preparation: DarwinJobPrepared,
	initial_frame: SyncedFrame,
	plan: DarwinCopyPlan<'job>,
	source: &'job ManagedRegularFile<'job>,
	source_root_id: RootCapabilityId,
	entry_attempted: bool,
}

impl PreparedDarwinJob<'_> {
	/// Returns the private name derived from the job UUIDv7.
	#[must_use]
	pub const fn name(&self) -> JobName {
		self.job.name()
	}

	/// Returns the signed envelope persisted under this job's private root.
	#[must_use]
	pub const fn owner(&self) -> &DarwinOwnerRecord {
		&self.owner
	}

	/// Returns the exact typed kind-1 preparation written to the journal.
	#[must_use]
	pub const fn preparation(&self) -> &DarwinJobPrepared {
		&self.preparation
	}

	/// Returns the successful Darwin file barrier for the first frame.
	#[must_use]
	pub const fn initial_frame(&self) -> &SyncedFrame {
		&self.initial_frame
	}
}

/// Checks the live plan bindings and opens a private job with a synchronized first frame.
///
/// The source and container must remain under the caller's managed APFS grants.
/// Obtain capability IDs and the signing profile from trusted inputs independent
/// of the plan. The job and journal leases remain held while the scoped operation
/// runs. Bootstrap issues no source data reads or publication authorization.
///
/// # Errors
/// Refuses mismatched authority, an occupied target, an inadmissible source, or
/// failed creation, signing or barriers. A possibly created job is retained with
/// its identity for reconciliation. An occupied private name is never adopted.
pub fn with_prepared_job<T>(
	plan: &DarwinCopyPlan<'_>,
	request: JobBootstrap<'_, '_>,
	operation: impl FnOnce(&mut PreparedDarwinJob<'_>) -> T,
) -> Result<T, JobBootstrapError> {
	let attempt = plan.attempt();
	if attempt.profile != request.profile.id {
		return Err(JobAdmissionError::ProfileMismatch.into());
	}
	if request.profile.owner_token.as_bytes() == attempt.job.as_bytes()
		|| request.profile.owner_token.as_bytes() == request.profile.id.as_bytes()
	{
		return Err(JobAdmissionError::Owner(OwnerError::InvalidToken).into());
	}
	if request.profile.signer.verifying_key().is_weak() {
		return Err(JobAdmissionError::Owner(OwnerError::InvalidSignature).into());
	}
	let name = JobName::from_uuid_bytes(*attempt.job.as_bytes())
		.map_err(JobAdmissionError::InvalidJobName)?;
	let destination = admit_destination(plan.destination(), request)?;
	check_source(plan.source(), request.source, request.source_root_id)?;
	with_admitted_job(plan, request, name, destination, operation)
}

fn with_admitted_job<T>(
	plan: &DarwinCopyPlan<'_>,
	request: JobBootstrap<'_, '_>,
	name: JobName,
	destination: DarwinRootBinding,
	operation: impl FnOnce(&mut PreparedDarwinJob<'_>) -> T,
) -> Result<T, JobBootstrapError> {
	let job = request
		.container
		.create_job_directory(name)
		.map_err(JobBootstrapError::Create)?;
	let JobPreparation {
		journal,
		journal_directory,
		owner,
		preparation,
		initial_frame,
	} = prepare_created_job(plan, request.profile, &job, destination)
		.map_err(|source| JobBootstrapError::Retained { job: name, source })?;
	let mut prepared = PreparedDarwinJob {
		journal,
		_journal_directory: journal_directory,
		job: &job,
		owner,
		preparation,
		initial_frame,
		plan: *plan,
		source: request.source,
		source_root_id: request.source_root_id,
		entry_attempted: false,
	};
	Ok(operation(&mut prepared))
}
