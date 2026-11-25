use exacopy_endpoint::UnixComponent;
use exacopy_journal::{DarwinFileIdentity, JournalJobId, OwnerError};
use exacopy_platform::macos::staging::MAX_STAGE_IO_BYTES;
use exacopy_platform::macos::staging::jobs::{
	JobName, RecoveryError, RecoveryFileObservation, RecoveryInventory, RecoveryJob,
	RecoveryRecord, RecoveryStageReader,
};
use exacopy_platform::macos::{BasicMetadata, ManagedObjectIdentity};

use crate::macos::job::native_identity;

use super::DarwinJobInspection;
use super::capabilities::{
	InspectionInventory, InspectionJob, InspectionRecord, InspectionStageReader, ObservationError,
	StageMetadata, StageObservation,
};
use super::protocol::Inspection;

pub(super) struct NativeSnapshot {
	stage_directory: Option<ManagedObjectIdentity>,
	stage: Option<RecoveryFileObservation>,
	target: Option<RecoveryFileObservation>,
}

impl From<Inspection<NativeSnapshot>> for DarwinJobInspection {
	fn from(inspection: Inspection<NativeSnapshot>) -> Self {
		Self {
			plan_bytes: inspection.plan_bytes,
			replay: inspection.replay,
			receipt: inspection.receipt,
			stage_directory: inspection.namespace.stage_directory,
			stage: inspection.namespace.stage,
			target: inspection.namespace.target,
		}
	}
}

impl InspectionJob for RecoveryJob<'_> {
	type Error = RecoveryError;
	type Snapshot = NativeSnapshot;
	type Record<'job>
		= RecoveryRecord<'job>
	where
		Self: 'job;
	type Inventory<'job>
		= RecoveryInventory<'job>
	where
		Self: 'job;

	fn matches_job(&self, expected: JournalJobId) -> bool {
		JobName::from_uuid_bytes(*expected.as_bytes()).ok() == Some(self.name())
	}

	fn identity(&self) -> Result<DarwinFileIdentity, OwnerError> {
		native_identity(RecoveryJob::identity(self))
	}

	fn owner_uid(&self) -> u32 {
		RecoveryJob::owner_uid(self)
	}

	fn observe_destination(&self) -> Result<DarwinFileIdentity, ObservationError<Self::Error>> {
		let identity =
			RecoveryJob::observe_destination(self).map_err(ObservationError::Platform)?;
		native_identity(identity).map_err(ObservationError::Identity)
	}

	fn open_plan(&self) -> Result<Self::Record<'_>, Self::Error> {
		RecoveryJob::open_plan(self)
	}

	fn open_owner(&self) -> Result<Self::Record<'_>, Self::Error> {
		RecoveryJob::open_owner(self)
	}

	fn open_first_segment(&self) -> Result<Self::Record<'_>, Self::Error> {
		RecoveryJob::open_first_segment(self)
	}

	fn open_receipt(&self) -> Result<Option<Self::Record<'_>>, Self::Error> {
		RecoveryJob::open_receipt(self)
	}

	fn inventory<'job>(
		&'job self,
		stage: UnixComponent<'job>,
		target: UnixComponent<'job>,
	) -> Result<Self::Inventory<'job>, Self::Error> {
		RecoveryJob::inventory(self, stage, target)
	}
}

impl InspectionRecord for RecoveryRecord<'_> {
	type Error = RecoveryError;

	fn length(&self) -> u64 {
		self.len()
	}

	fn revalidate(&self) -> Result<(), Self::Error> {
		RecoveryRecord::revalidate(self)
	}
}

impl InspectionInventory for RecoveryInventory<'_> {
	type Error = RecoveryError;
	type Snapshot = NativeSnapshot;
	type Stage = RecoveryFileObservation;
	type Reader<'inventory>
		= RecoveryStageReader<'inventory>
	where
		Self: 'inventory;

	const MAX_READ_BYTES: usize = MAX_STAGE_IO_BYTES;

	fn stage_directory_identity(&self) -> Option<DarwinFileIdentity> {
		RecoveryInventory::stage_directory_identity(self).and_then(|id| native_identity(id).ok())
	}

	fn stage(&self) -> Option<StageObservation<Self::Stage>> {
		let held = RecoveryInventory::stage(self)?;
		Some(StageObservation {
			held,
			identity: native_identity(held.identity()).ok()?,
			length: held.length(),
		})
	}

	fn open_stage_read_back(&self, stage: Self::Stage) -> Result<Self::Reader<'_>, Self::Error> {
		RecoveryInventory::open_stage_read_back(self, stage)
	}

	fn revalidate(&self) -> Result<(), Self::Error> {
		RecoveryInventory::revalidate(self)
	}

	fn snapshot(&self) -> Self::Snapshot {
		NativeSnapshot {
			stage_directory: RecoveryInventory::stage_directory_identity(self),
			stage: RecoveryInventory::stage(self),
			target: self.target(),
		}
	}
}

impl InspectionStageReader for RecoveryStageReader<'_> {
	type Error = RecoveryError;

	fn initial_metadata(&self) -> StageMetadata {
		metadata(RecoveryStageReader::initial_metadata(self))
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		RecoveryStageReader::read_exact_at(self, offset, bytes)
	}

	fn revalidate(&self) -> Result<StageMetadata, Self::Error> {
		RecoveryStageReader::revalidate(self).map(metadata)
	}
}

fn metadata(observed: BasicMetadata) -> StageMetadata {
	StageMetadata {
		uid: observed.uid(),
		gid: observed.gid(),
		mode: observed.mode(),
		atime: (observed.atime().seconds(), observed.atime().nanoseconds()),
		mtime: (observed.mtime().seconds(), observed.mtime().nanoseconds()),
	}
}
