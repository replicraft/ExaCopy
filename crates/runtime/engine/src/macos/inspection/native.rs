use std::io::{self, Read};

use exacopy_endpoint::UnixComponent;
use exacopy_journal::{DarwinFileIdentity, JournalJobId, OwnerError};
use exacopy_platform::macos::staging::MAX_STAGE_IO_BYTES;
use exacopy_platform::macos::staging::jobs::{
	JobName, RecoveryError, RecoveryFileObservation, RecoveryInventory, RecoveryJob,
	RecoveryRecord, RecoveryStageReader,
};
use exacopy_platform::macos::{BasicMetadata, ManagedObjectIdentity};
use exacopy_transfer::macos::inspection::{
	Inspection, InspectionInventory, InspectionJob, InspectionRecord, InspectionStageReader,
	ObservationError, StageMetadata, StageObservation,
};

use crate::macos::job::native_identity;

use super::DarwinJobInspection;

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

pub(super) struct HeldJob<'job>(pub(super) &'job RecoveryJob<'job>);

impl InspectionJob for HeldJob<'_> {
	type Error = RecoveryError;
	type Snapshot = NativeSnapshot;
	type Record<'job>
		= HeldRecord<'job>
	where
		Self: 'job;
	type Inventory<'job>
		= HeldInventory<'job>
	where
		Self: 'job;

	fn matches_job(&self, expected: JournalJobId) -> bool {
		JobName::from_uuid_bytes(*expected.as_bytes()).ok() == Some(self.0.name())
	}

	fn identity(&self) -> Result<DarwinFileIdentity, OwnerError> {
		native_identity(self.0.identity())
	}

	fn owner_uid(&self) -> u32 {
		self.0.owner_uid()
	}

	fn observe_destination(&self) -> Result<DarwinFileIdentity, ObservationError<Self::Error>> {
		let identity = self
			.0
			.observe_destination()
			.map_err(ObservationError::Platform)?;
		native_identity(identity).map_err(ObservationError::Identity)
	}

	fn open_plan(&self) -> Result<Self::Record<'_>, Self::Error> {
		self.0.open_plan().map(HeldRecord)
	}

	fn open_owner(&self) -> Result<Self::Record<'_>, Self::Error> {
		self.0.open_owner().map(HeldRecord)
	}

	fn open_first_segment(&self) -> Result<Self::Record<'_>, Self::Error> {
		self.0.open_first_segment().map(HeldRecord)
	}

	fn open_receipt(&self) -> Result<Option<Self::Record<'_>>, Self::Error> {
		self.0.open_receipt().map(|record| record.map(HeldRecord))
	}

	fn inventory<'job>(
		&'job self,
		stage: UnixComponent<'job>,
		target: UnixComponent<'job>,
	) -> Result<Self::Inventory<'job>, Self::Error> {
		self.0.inventory(stage, target).map(HeldInventory)
	}
}

pub(super) struct HeldRecord<'job>(RecoveryRecord<'job>);

impl Read for HeldRecord<'_> {
	fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
		self.0.read(bytes)
	}
}

impl InspectionRecord for HeldRecord<'_> {
	type Error = RecoveryError;

	fn length(&self) -> u64 {
		self.0.len()
	}

	fn revalidate(&self) -> Result<(), Self::Error> {
		self.0.revalidate()
	}
}

pub(super) struct HeldInventory<'job>(RecoveryInventory<'job>);

impl InspectionInventory for HeldInventory<'_> {
	type Error = RecoveryError;
	type Snapshot = NativeSnapshot;
	type Stage = RecoveryFileObservation;
	type Reader<'inventory>
		= HeldStageReader<'inventory>
	where
		Self: 'inventory;

	const MAX_READ_BYTES: usize = MAX_STAGE_IO_BYTES;

	fn stage_directory_identity(&self) -> Option<DarwinFileIdentity> {
		self.0
			.stage_directory_identity()
			.and_then(|id| native_identity(id).ok())
	}

	fn stage(&self) -> Option<StageObservation<Self::Stage>> {
		let held = self.0.stage()?;
		Some(StageObservation {
			held,
			identity: native_identity(held.identity()).ok()?,
			length: held.length(),
		})
	}

	fn open_stage_read_back(&self, stage: Self::Stage) -> Result<Self::Reader<'_>, Self::Error> {
		self.0.open_stage_read_back(stage).map(HeldStageReader)
	}

	fn revalidate(&self) -> Result<(), Self::Error> {
		self.0.revalidate()
	}

	fn snapshot(&self) -> Self::Snapshot {
		NativeSnapshot {
			stage_directory: self.0.stage_directory_identity(),
			stage: self.0.stage(),
			target: self.0.target(),
		}
	}
}

pub(super) struct HeldStageReader<'inventory>(RecoveryStageReader<'inventory>);

impl InspectionStageReader for HeldStageReader<'_> {
	type Error = RecoveryError;

	fn initial_metadata(&self) -> StageMetadata {
		metadata(self.0.initial_metadata())
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		self.0.read_exact_at(offset, bytes)
	}

	fn revalidate(&self) -> Result<StageMetadata, Self::Error> {
		self.0.revalidate().map(metadata)
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
