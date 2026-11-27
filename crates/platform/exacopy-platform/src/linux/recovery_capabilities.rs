use exacopy_endpoint::linux_copy::CopySourceObservation;
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_recovery::{
	PublicStageJobView, RecoveryInventoryView, RecoveryJobView, RecoveryRecord,
};
use exacopy_endpoint::{ReadView, UnixComponent};

use super::{
	ExtendedAttributes, FileIdentity, ReadError, RecoveryFile, RecoveryInventory, RecoveryJob,
	StageError,
};

#[cfg(test)]
#[path = "../../tests/unit/linux_recovery_capabilities.rs"]
mod tests;

impl ReadView for RecoveryFile {
	type Error = ReadError;

	fn length(&self) -> u64 {
		self.len()
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.check_logical_eof()?;
		RecoveryFile::recheck_observation(self)
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		RecoveryFile::read_exact_at(self, offset, bytes)
	}
}

impl RecoveryRecord for RecoveryFile {
	type Identity = FileIdentity;

	fn identity(&self) -> Self::Identity {
		RecoveryFile::identity(self)
	}

	fn observation(&self) -> CopySourceObservation {
		RecoveryFile::observation(self).into()
	}

	fn recheck_inode(&self) -> Result<(), Self::Error> {
		RecoveryFile::recheck_observation(self)
	}

	fn check_logical_eof(&self) -> Result<(), Self::Error> {
		RecoveryFile::check_logical_eof(self)
	}

	fn extended_attributes(&self) -> Result<ExtendedAttributes, Self::Error> {
		RecoveryFile::extended_attributes(self)
	}
}

impl RecoveryJobView for RecoveryJob<'_> {
	type ReadError = ReadError;
	type NamespaceError = StageError;
	type Record = RecoveryFile;
	type Inventory<'job>
		= RecoveryInventory<'job>
	where
		Self: 'job;

	fn identities(&self) -> (JobFileIdentity, JobFileIdentity) {
		(self.identity().into(), self.destination_identity().into())
	}

	fn open_owner(&self) -> Result<Self::Record, Self::NamespaceError> {
		RecoveryJob::open_owner(self)
	}

	fn open_plan(&self) -> Result<Self::Record, Self::NamespaceError> {
		RecoveryJob::open_plan(self)
	}

	fn open_first_segment(&self) -> Result<Self::Record, Self::NamespaceError> {
		RecoveryJob::open_first_segment(self)
	}

	fn open_checkpoint(&self, ordinal: u32) -> Result<Self::Record, Self::NamespaceError> {
		self.open_checkpoint_page(ordinal)
	}

	fn open_optional_receipt(&self) -> Result<Option<Self::Record>, Self::NamespaceError> {
		RecoveryJob::open_optional_receipt(self)
	}

	fn inventory(
		&self,
		stage: UnixComponent<'_>,
		target: UnixComponent<'_>,
	) -> Result<Self::Inventory<'_>, Self::NamespaceError> {
		RecoveryJob::inventory(self, stage, target)
	}
}

impl PublicStageJobView for RecoveryJob<'_> {
	fn open_optional_owner(&self) -> Result<Option<Self::Record>, Self::NamespaceError> {
		RecoveryJob::open_optional_owner(self)
	}

	fn open_optional_plan(&self) -> Result<Option<Self::Record>, Self::NamespaceError> {
		RecoveryJob::open_optional_plan(self)
	}

	fn open_optional_first_segment(&self) -> Result<Option<Self::Record>, Self::NamespaceError> {
		RecoveryJob::open_optional_first_segment(self)
	}
}

impl RecoveryInventoryView for RecoveryInventory<'_> {
	type Record = RecoveryFile;
	type Error = StageError;

	fn stage(&self) -> Option<&Self::Record> {
		RecoveryInventory::stage(self)
	}

	fn target(&self) -> Option<&Self::Record> {
		RecoveryInventory::target(self)
	}

	fn stage_directory_identity(&self) -> Option<JobFileIdentity> {
		RecoveryInventory::stage_directory_identity(self).map(Into::into)
	}

	fn recheck(&self) -> Result<(), Self::Error> {
		RecoveryInventory::recheck(self)
	}
}
