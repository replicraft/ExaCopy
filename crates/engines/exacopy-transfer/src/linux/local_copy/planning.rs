use exacopy_endpoint::linux_copy::{
	CopyDestinationView, CopySource, CopySourceRoot, TargetObservation,
};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_staging::StagingSource as _;
use exacopy_endpoint::{ReadView as _, UnixComponent};
use exacopy_journal::{
	DestinationRootBinding, LinuxFileIdentity, ObservedTimestamp, RootCapabilityId,
};

use crate::linux_staging::check_source;

use super::super::{DestinationPlanBinding, LocalCopyPlan, PlanAttempt, SourcePlanBinding};
use super::CopyError;

/// Independently held source and destination views and their authorization IDs.
pub struct PlanningRoots<'root, Source, Destination> {
	/// Authorizes read-only selection beneath the held source root.
	pub source: &'root Source,
	/// Identifies the independent source authorization.
	pub source_id: RootCapabilityId,
	/// Authorizes observations beneath the held destination root.
	pub destination: &'root Destination,
	/// Identifies the independent destination authorization.
	pub destination_id: RootCapabilityId,
}

impl<S, D> Clone for PlanningRoots<'_, S, D> {
	fn clone(&self) -> Self {
		*self
	}
}

impl<S, D> Copy for PlanningRoots<'_, S, D> {}

/// Admits one regular source and an absent target for a Linux preserve-copy plan.
///
/// The held views report observations. The transfer policy admits the source
/// metadata and binds both capabilities to the exact selected names and attempt.
/// # Errors
/// Refuses occupied targets, unsupported source observations, and invalid bindings.
pub fn plan_with_capabilities<'name, S, D, P>(
	roots: PlanningRoots<'_, S, D>,
	attempt: PlanAttempt<'name>,
	source: UnixComponent<'name>,
	target: UnixComponent<'name>,
) -> Result<LocalCopyPlan<'name>, CopyError<S::Error, D::Error, P>>
where
	S: CopySourceRoot,
	D: CopyDestinationView,
{
	check_absent(roots.destination, target)?;
	let file = roots
		.source
		.open_regular(source)
		.map_err(CopyError::Source)?;
	check_source(&file).map_err(CopyError::SourcePolicy)?;
	let source = capture_source(&roots, &file, source)?;
	let destination = DestinationPlanBinding {
		root: destination_binding(&roots),
		component: target,
	};
	LocalCopyPlan::new(attempt, source, destination).map_err(CopyError::Plan)
}

pub(super) fn check_absent<S, D: CopyDestinationView, P>(
	root: &D,
	name: UnixComponent<'_>,
) -> Result<(), CopyError<S, D::Error, P>> {
	match root
		.observe_target(name)
		.map_err(CopyError::InspectTarget)?
	{
		TargetObservation::Absent => Ok(()),
		TargetObservation::Occupied => Err(CopyError::Conflict),
	}
}

pub(super) fn destination_binding<S, D: CopyDestinationView>(
	roots: &PlanningRoots<'_, S, D>,
) -> DestinationRootBinding {
	DestinationRootBinding {
		id: roots.destination_id,
		identity: journal_identity(roots.destination.identity()),
	}
}

pub(super) fn source_root_identity(root: &impl CopySourceRoot) -> LinuxFileIdentity {
	journal_identity(root.identity())
}

pub(super) fn capture_source<'name, S, D, P>(
	roots: &PlanningRoots<'_, S, D>,
	file: &S::Source,
	name: UnixComponent<'name>,
) -> Result<SourcePlanBinding<'name>, CopyError<S::Error, D::Error, P>>
where
	S: CopySourceRoot,
	D: CopyDestinationView,
{
	let observation = file.copy_observation();
	let modified_at = observation.modified_at;
	let changed_at = observation.changed_at;
	Ok(SourcePlanBinding {
		root_id: roots.source_id,
		root_identity: source_root_identity(roots.source),
		file_identity: journal_identity(file.identity().into()),
		length: file.length(),
		modified_at: ObservedTimestamp::new(modified_at.seconds, modified_at.nanoseconds)
			.map_err(CopyError::Preparation)?,
		changed_at: ObservedTimestamp::new(changed_at.seconds, changed_at.nanoseconds)
			.map_err(CopyError::Preparation)?,
		component: name,
	})
}

pub(super) fn journal_identity(identity: JobFileIdentity) -> LinuxFileIdentity {
	LinuxFileIdentity::new(identity.device, identity.inode)
}
