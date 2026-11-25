//! Synchronized preparation of owner-private managed APFS jobs.

use exacopy_journal::{
	DarwinJobPrepared, DarwinOwnerRecord, DarwinRootBinding, DurableJournal, RootCapabilityId,
	SyncedFrame,
};
use exacopy_platform::macos::ManagedRegularFile;
use exacopy_platform::macos::staging::StageDirectory;
use exacopy_platform::macos::staging::jobs::{DarwinJournalSegment, JobDirectory, JobName};

use exacopy_transfer::macos::job::ProfileError;
use exacopy_transfer::macos::job::bootstrap::{
	BootstrapInputs, CreatedJob, JobCreationFailure, JobPreparation, admit_and_create, prepare,
};
use exacopy_transfer::macos::job::entry::EntryAttempt;

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
pub use error::{JobAdmissionError, JobBootstrapError, JobPreparationError};
pub use exacopy_transfer::macos::job::{DarwinJobProfile, JobPreparationStep};

#[cfg(test)]
use self::admission::admit_destination;
pub(super) use self::admission::native_identity;
use self::admission::{HeldDestination, HeldSource, destination_failure, source_failure};
use self::bootstrap::NativeJob;

#[cfg(test)]
use exacopy_journal::{JournalFileBarrier, frame::FrameKind};

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
	journal: DurableJournal<DarwinJournalSegment<'job>>,
	job: &'job JobDirectory<'job>,
	owner: DarwinOwnerRecord,
	preparation: DarwinJobPrepared,
	initial_frame: SyncedFrame,
	plan: DarwinCopyPlan<'job>,
	source: &'job ManagedRegularFile<'job>,
	source_root_id: RootCapabilityId,
	entry_attempt: EntryAttempt,
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
	let (root, source) = (
		HeldDestination(request.container),
		HeldSource(request.source),
	);
	let CreatedJob {
		name,
		directory,
		destination,
	} = admit_and_create(
		plan,
		BootstrapInputs {
			source: &source,
			source_root_id: request.source_root_id,
			destination_root_id: request.destination_root_id,
			profile: request.profile,
		},
		&root,
	)
	.map_err(|failure| match failure {
		JobCreationFailure::Profile(ProfileError::Mismatch) => {
			JobAdmissionError::ProfileMismatch.into()
		}
		JobCreationFailure::Profile(ProfileError::Owner(error)) => {
			JobAdmissionError::Owner(error).into()
		}
		JobCreationFailure::Name(error) => JobAdmissionError::InvalidJobName(error).into(),
		JobCreationFailure::Destination(error) => destination_failure(error).into(),
		JobCreationFailure::Source(error) => source_failure(error).into(),
		JobCreationFailure::Create(error) => JobBootstrapError::Create(error),
	})?;
	with_created_job(plan, request, name, &directory, destination, operation)
}

#[cfg(test)]
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
	with_created_job(plan, request, name, &job, destination, operation)
}

fn with_created_job<T>(
	plan: &DarwinCopyPlan<'_>,
	request: JobBootstrap<'_, '_>,
	name: JobName,
	job: &JobDirectory<'_>,
	destination: DarwinRootBinding,
	operation: impl FnOnce(&mut PreparedDarwinJob<'_>) -> T,
) -> Result<T, JobBootstrapError> {
	let native_job = NativeJob(job);
	let JobPreparation {
		journal,
		owner,
		preparation,
		initial_frame,
	} = prepare(plan, request.profile, &native_job, destination)
		.map_err(JobPreparationError::from)
		.map_err(|source| JobBootstrapError::Retained { job: name, source })?;
	let mut prepared = PreparedDarwinJob {
		journal,
		job,
		owner,
		preparation,
		initial_frame,
		plan: *plan,
		source: request.source,
		source_root_id: request.source_root_id,
		entry_attempt: EntryAttempt::default(),
	};
	Ok(operation(&mut prepared))
}
