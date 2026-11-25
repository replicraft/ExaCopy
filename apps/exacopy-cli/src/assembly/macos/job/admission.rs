use exacopy_endpoint::UnixComponent;
use exacopy_journal::{
	DarwinFileIdentity, DarwinVolumeIdentity, OwnerError, OwnerTimestamp, RootCapabilityId,
};
use exacopy_model::InvalidJobId;
use exacopy_platform::macos::staging::{
	StageDirectory,
	jobs::{JobDirectory, JobError, JobName},
};
use exacopy_platform::macos::{
	ManagedObjectIdentity, ManagedReadError, ManagedRegularFile, ManagedTimestamp,
};
use exacopy_transfer::macos::job::admission::{
	self, AdmissionFailure, ReadOnlySource, SourceIdentities, SourceMetadataObservation, Timestamp,
};

use exacopy_transfer::macos::job::bootstrap::PrivateJobRoot;

use super::JobAdmissionError;
use crate::assembly::macos::plan::SourcePlanBinding;

#[cfg(test)]
use {
	super::JobBootstrap, crate::assembly::macos::plan::DestinationPlanBinding,
	exacopy_journal::DarwinRootBinding,
};

pub(super) struct HeldSource<'source>(pub(super) &'source ManagedRegularFile<'source>);
pub(super) struct HeldDestination<'root>(pub(super) &'root StageDirectory<'root>);

impl PrivateJobRoot for HeldDestination<'_> {
	type Name = JobName;
	type Directory<'root>
		= JobDirectory<'root>
	where
		Self: 'root;
	type Error = JobError;

	fn job_name(&self, bytes: [u8; 16]) -> Result<Self::Name, InvalidJobId> {
		JobName::from_uuid_bytes(bytes)
	}

	fn observe_empty(
		&self,
		target: UnixComponent<'_>,
	) -> Result<DarwinFileIdentity, AdmissionFailure<JobError>> {
		let observed = self
			.0
			.observe_empty_job_destination(target)
			.map_err(AdmissionFailure::Adapter)?;
		native_identity(observed).map_err(AdmissionFailure::Identity)
	}

	fn create_job(&self, name: JobName) -> Result<JobDirectory<'_>, JobError> {
		self.0.create_job_directory(name)
	}
}

#[cfg(test)]
pub(super) fn admit_destination(
	planned: DestinationPlanBinding<'_>,
	request: JobBootstrap<'_, '_>,
) -> Result<DarwinRootBinding, JobAdmissionError> {
	let root = HeldDestination(request.container);
	admission::bind_destination(planned, request.destination_root_id, |target| {
		root.observe_empty(target)
	})
	.map_err(destination_failure)
}

pub(super) fn destination_failure(failure: AdmissionFailure<JobError>) -> JobAdmissionError {
	match failure {
		AdmissionFailure::Mismatch => JobAdmissionError::DestinationMismatch,
		AdmissionFailure::Identity(error) => JobAdmissionError::Identity(error),
		AdmissionFailure::Adapter(error) => JobAdmissionError::Destination(error),
	}
}

pub(super) fn check_source(
	planned: SourcePlanBinding<'_>,
	source: &ManagedRegularFile<'_>,
	source_root_id: RootCapabilityId,
) -> Result<(), JobAdmissionError> {
	admission::check_source(planned, &HeldSource(source), source_root_id).map_err(source_failure)
}

pub(super) fn source_failure(failure: AdmissionFailure<ManagedReadError>) -> JobAdmissionError {
	match failure {
		AdmissionFailure::Mismatch => JobAdmissionError::SourceMismatch,
		AdmissionFailure::Identity(error) => JobAdmissionError::Identity(error),
		AdmissionFailure::Adapter(error) => JobAdmissionError::Source(error),
	}
}

impl ReadOnlySource for HeldSource<'_> {
	type Error = ManagedReadError;

	fn component(&self) -> UnixComponent<'_> {
		self.0.component()
	}

	fn length(&self) -> u64 {
		self.0.length()
	}

	fn observe_identities(&self) -> Result<SourceIdentities, AdmissionFailure<Self::Error>> {
		let identities = self
			.0
			.observe_identities()
			.map_err(AdmissionFailure::Adapter)?;
		Ok(SourceIdentities {
			root: native_identity(identities.parent).map_err(AdmissionFailure::Identity)?,
			file: native_identity(identities.file).map_err(AdmissionFailure::Identity)?,
		})
	}

	fn check_pre_read_metadata(&self) -> Result<SourceMetadataObservation, Self::Error> {
		let observed = self.0.check_pre_read_basic_metadata()?;
		Ok(SourceMetadataObservation {
			uid: observed.uid(),
			gid: observed.gid(),
			mode: observed.mode(),
			accessed: observed_time(observed.atime()),
			modified: observed_time(observed.mtime()),
		})
	}

	fn change_time(&self) -> Result<Timestamp, Self::Error> {
		self.0.change_time().map(observed_time)
	}
}

fn observed_time(time: ManagedTimestamp) -> Timestamp {
	Timestamp {
		seconds: time.seconds(),
		nanoseconds: time.nanoseconds(),
	}
}

pub(in crate::assembly::macos) fn native_identity(
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
