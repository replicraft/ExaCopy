use exacopy_journal::{
	DarwinFileIdentity, DarwinRootBinding, DarwinVolumeIdentity, ObservedTimestamp, OwnerError,
	OwnerTimestamp, RootCapabilityId,
};
use exacopy_platform::macos::{ManagedObjectIdentity, ManagedRegularFile, ManagedTimestamp};

use super::{JobAdmissionError, JobBootstrap};
use crate::macos::plan::{DestinationPlanBinding, SourcePlanBinding};

pub(super) fn admit_destination(
	planned: DestinationPlanBinding<'_>,
	request: JobBootstrap<'_, '_>,
) -> Result<DarwinRootBinding, JobAdmissionError> {
	if request.destination_root_id != planned.root_id {
		return Err(JobAdmissionError::DestinationMismatch);
	}
	let observed = request
		.container
		.observe_empty_job_destination(planned.component)
		.map_err(JobAdmissionError::Destination)?;
	let identity = native_identity(observed).map_err(JobAdmissionError::Identity)?;
	if identity != planned.root_identity {
		return Err(JobAdmissionError::DestinationMismatch);
	}
	Ok(DarwinRootBinding {
		id: request.destination_root_id,
		identity,
	})
}

pub(super) fn check_source(
	planned: SourcePlanBinding<'_>,
	source: &ManagedRegularFile<'_>,
	source_root_id: RootCapabilityId,
) -> Result<(), JobAdmissionError> {
	if (source_root_id, source.component(), source.length())
		!= (planned.root_id, planned.component, planned.length)
	{
		return Err(JobAdmissionError::SourceMismatch);
	}
	let identities = source
		.observe_identities()
		.map_err(JobAdmissionError::Source)?;
	let root = native_identity(identities.parent).map_err(JobAdmissionError::Identity)?;
	let file = native_identity(identities.file).map_err(JobAdmissionError::Identity)?;
	if (root, file) != (planned.root_identity, planned.file_identity) {
		return Err(JobAdmissionError::SourceMismatch);
	}
	let live = source
		.check_pre_read_basic_metadata()
		.map_err(JobAdmissionError::Source)?;
	let change_time = source.change_time().map_err(JobAdmissionError::Source)?;
	let metadata = planned.metadata;
	if (live.uid(), live.gid(), live.mode())
		!= (
			metadata.uid().get(),
			metadata.gid(),
			u32::from(metadata.mode()),
		)
		|| !same_time(live.atime(), metadata.accessed_at())
		|| !same_time(live.mtime(), metadata.modified_at())
		|| !same_time(change_time, metadata.changed_at())
	{
		return Err(JobAdmissionError::SourceMismatch);
	}
	Ok(())
}

fn same_time(native: ManagedTimestamp, planned: ObservedTimestamp) -> bool {
	(native.seconds(), native.nanoseconds()) == (planned.seconds(), planned.nanoseconds())
}

pub(in crate::macos) fn native_identity(
	observed: ManagedObjectIdentity,
) -> Result<DarwinFileIdentity, OwnerError> {
	let volume = DarwinVolumeIdentity::new(observed.device(), observed.physical_fsid())?;
	let birth = observed.birth();
	Ok(DarwinFileIdentity::new(
		volume,
		observed.inode(),
		observed.generation(),
		OwnerTimestamp::new(birth.seconds(), birth.nanoseconds())?,
	))
}
