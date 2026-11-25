use exacopy_endpoint::UnixComponent;
use exacopy_journal::{
	DarwinFileIdentity, DarwinRootBinding, DarwinVolumeIdentity, OwnerError, OwnerTimestamp,
	RootCapabilityId,
};
use exacopy_platform::macos::{
	ManagedObjectIdentity, ManagedReadError, ManagedRegularFile, ManagedTimestamp,
};

use super::{JobAdmissionError, JobBootstrap};
use crate::macos::plan::{DestinationPlanBinding, SourcePlanBinding};

mod engine;

use engine::{
	AdmissionFailure, ReadOnlySource, SourceIdentities, SourceMetadataObservation, Timestamp,
};

pub(super) fn admit_destination(
	planned: DestinationPlanBinding<'_>,
	request: JobBootstrap<'_, '_>,
) -> Result<DarwinRootBinding, JobAdmissionError> {
	engine::bind_destination(planned, request.destination_root_id, |component| {
		let observed = request
			.container
			.observe_empty_job_destination(component)
			.map_err(AdmissionFailure::Adapter)?;
		native_identity(observed).map_err(AdmissionFailure::Identity)
	})
	.map_err(|failure| match failure {
		AdmissionFailure::Mismatch => JobAdmissionError::DestinationMismatch,
		AdmissionFailure::Identity(error) => JobAdmissionError::Identity(error),
		AdmissionFailure::Adapter(error) => JobAdmissionError::Destination(error),
	})
}

pub(super) fn check_source(
	planned: SourcePlanBinding<'_>,
	source: &ManagedRegularFile<'_>,
	source_root_id: RootCapabilityId,
) -> Result<(), JobAdmissionError> {
	engine::check_source(planned, source, source_root_id).map_err(|failure| match failure {
		AdmissionFailure::Mismatch => JobAdmissionError::SourceMismatch,
		AdmissionFailure::Identity(error) => JobAdmissionError::Identity(error),
		AdmissionFailure::Adapter(error) => JobAdmissionError::Source(error),
	})
}

impl ReadOnlySource for ManagedRegularFile<'_> {
	type Error = ManagedReadError;

	fn component(&self) -> UnixComponent<'_> {
		self.component()
	}

	fn length(&self) -> u64 {
		self.length()
	}

	fn observe_identities(&self) -> Result<SourceIdentities, AdmissionFailure<Self::Error>> {
		let identities = self
			.observe_identities()
			.map_err(AdmissionFailure::Adapter)?;
		Ok(SourceIdentities {
			root: native_identity(identities.parent).map_err(AdmissionFailure::Identity)?,
			file: native_identity(identities.file).map_err(AdmissionFailure::Identity)?,
		})
	}

	fn check_pre_read_metadata(&self) -> Result<SourceMetadataObservation, Self::Error> {
		let observed = self.check_pre_read_basic_metadata()?;
		Ok(SourceMetadataObservation {
			uid: observed.uid(),
			gid: observed.gid(),
			mode: observed.mode(),
			accessed: observed_time(observed.atime()),
			modified: observed_time(observed.mtime()),
		})
	}

	fn change_time(&self) -> Result<Timestamp, Self::Error> {
		self.change_time().map(observed_time)
	}
}

fn observed_time(time: ManagedTimestamp) -> Timestamp {
	Timestamp {
		seconds: time.seconds(),
		nanoseconds: time.nanoseconds(),
	}
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
