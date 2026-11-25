use exacopy_endpoint::UnixComponent;
use exacopy_journal::{DarwinFileIdentity, DarwinRootBinding, RootCapabilityId};
use exacopy_model::InvalidJobId;

use super::super::admission::{self, AdmissionFailure, ReadOnlySource};
use super::super::{DarwinJobProfile, ProfileError, validate_profile};
use crate::macos::plan::DarwinCopyPlan;

/// The destination authority and exclusive private job creation capability.
pub trait PrivateJobRoot {
	/// The adapter's checked private namespace component.
	type Name: Copy;
	/// A held private job directory.
	type Directory<'root>
	where
		Self: 'root;
	/// The adapter's destination observation and creation failures.
	type Error;

	/// Translates the planned model job identity to a native private name.
	fn job_name(&self, bytes: [u8; 16]) -> Result<Self::Name, InvalidJobId>;

	/// Revalidates the private container and observes the public target absent.
	fn observe_empty(
		&self,
		target: UnixComponent<'_>,
	) -> Result<DarwinFileIdentity, AdmissionFailure<Self::Error>>;

	/// Exclusively creates the private job directory under the held container.
	fn create_job(&self, name: Self::Name) -> Result<Self::Directory<'_>, Self::Error>;
}

/// Independently selected capabilities and signing profile for one job admission.
pub struct BootstrapInputs<'source, 'profile, S> {
	/// Held read-only source.
	pub source: &'source S,
	/// Independently selected source authority.
	pub source_root_id: RootCapabilityId,
	/// Independently selected destination authority.
	pub destination_root_id: RootCapabilityId,
	/// Independently selected signing profile.
	pub profile: DarwinJobProfile<'profile>,
}

/// A newly created job bound to the checked destination observation.
pub struct CreatedJob<N, D> {
	/// Exact checked private name.
	pub name: N,
	/// Held directory created exclusively for this attempt.
	pub directory: D,
	/// Destination identity admitted before creation.
	pub destination: DarwinRootBinding,
}

/// The admission or creation boundary at which bootstrap stopped.
#[derive(Debug)]
pub enum JobCreationFailure<S, D> {
	/// Independently selected signing credentials do not authorize this plan.
	Profile(ProfileError),
	/// The selected job identity cannot be represented as a private name.
	Name(InvalidJobId),
	/// Destination authority, identity or target absence could not be established.
	Destination(AdmissionFailure<D>),
	/// Source authority, identity or required metadata could not be established.
	Source(AdmissionFailure<S>),
	/// Exclusive creation failed or may have created a retained entry.
	Create(D),
}

type Creation<'root, S, D> = Result<
	CreatedJob<<D as PrivateJobRoot>::Name, <D as PrivateJobRoot>::Directory<'root>>,
	JobCreationFailure<<S as ReadOnlySource>::Error, <D as PrivateJobRoot>::Error>,
>;

/// Admits the plan in prerequisite order, then exclusively creates one private job.
/// # Errors
/// Reports the first refused prerequisite or the exact native creation failure.
pub fn admit_and_create<'root, S: ReadOnlySource, D: PrivateJobRoot>(
	plan: &DarwinCopyPlan<'_>,
	inputs: BootstrapInputs<'_, '_, S>,
	root: &'root D,
) -> Creation<'root, S, D> {
	let attempt = plan.attempt();
	validate_profile(attempt, inputs.profile).map_err(JobCreationFailure::Profile)?;
	let name = root
		.job_name(*attempt.job.as_bytes())
		.map_err(JobCreationFailure::Name)?;
	let destination =
		admission::bind_destination(plan.destination(), inputs.destination_root_id, |target| {
			root.observe_empty(target)
		})
		.map_err(JobCreationFailure::Destination)?;
	admission::check_source(plan.source(), inputs.source, inputs.source_root_id)
		.map_err(JobCreationFailure::Source)?;
	let directory = root.create_job(name).map_err(JobCreationFailure::Create)?;
	Ok(CreatedJob {
		name,
		directory,
		destination,
	})
}
