use exacopy_endpoint::linux_staging::{
	SourceMetadata, StageReader, StageWriter, StagingDirectory, StagingSource,
};
use exacopy_endpoint::{IoError, UnixComponent};
use exacopy_model::CopyBinding;

use super::{
	ClosedStage, ExtendedAttributes, FileIdentity, SourceFile, SourceObservation, SourceTimestamp,
	StageDirectory, StageError, WriteStage,
};

impl SourceMetadata for SourceObservation {
	type Timestamp = SourceTimestamp;

	fn mode(self) -> u32 {
		SourceObservation::mode(&self)
	}

	fn accessed_at(self) -> Self::Timestamp {
		SourceObservation::accessed_at(&self)
	}
}

impl StagingSource for SourceFile {
	type Identity = FileIdentity;
	type Metadata = SourceObservation;

	fn identity(&self) -> Self::Identity {
		SourceFile::identity(self)
	}

	fn metadata(&self) -> Self::Metadata {
		self.observation()
	}

	fn extended_attributes(&self) -> Result<ExtendedAttributes, Self::Error> {
		SourceFile::extended_attributes(self)
	}

	fn recheck_metadata(&self) -> Result<(), Self::Error> {
		SourceFile::recheck_observation(self)
	}
}

impl StagingDirectory for StageDirectory<'_> {
	type Error = StageError;
	type Identity = FileIdentity;
	type Metadata = SourceObservation;
	type Writer<'stage>
		= WriteStage<'stage>
	where
		Self: 'stage;

	fn create_file(
		&self,
		name: UnixComponent<'_>,
		target: UnixComponent<'_>,
		binding: CopyBinding,
	) -> Result<Self::Writer<'_>, StageError> {
		StageDirectory::create_file(self, name, target, binding)
	}

	fn sync_directory(&self) -> Result<(), StageError> {
		StageDirectory::sync_directory(self)
	}
}

impl<'stage> StageWriter for WriteStage<'stage> {
	type Identity = FileIdentity;
	type Metadata = SourceObservation;
	type Error = StageError;
	type Reader = ClosedStage<'stage>;

	fn identity(&self) -> Self::Identity {
		WriteStage::identity(self)
	}

	fn check_ownership(&self, metadata: Self::Metadata) -> Result<(), Self::Error> {
		WriteStage::check_ownership(self, metadata)
	}

	fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), Self::Error> {
		WriteStage::write_all_at(self, offset, bytes)
	}

	fn set_len(&mut self, length: u64) -> Result<(), Self::Error> {
		WriteStage::set_len(self, length)
	}

	fn flush(&mut self) -> Result<(), Self::Error> {
		WriteStage::flush(self)
	}

	fn close_writes(self) -> Result<Self::Reader, Self::Error> {
		WriteStage::close_writes(self)
	}
}

impl StageReader for ClosedStage<'_> {
	type Identity = FileIdentity;
	type Metadata = SourceObservation;
	type Error = StageError;

	fn identity(&self) -> Self::Identity {
		ClosedStage::identity(self)
	}

	fn length(&self) -> u64 {
		ClosedStage::length(self)
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), IoError> {
		ClosedStage::read_exact_at(self, offset, bytes)
	}

	fn apply_metadata_with_access_time(
		self,
		metadata: Self::Metadata,
		accessed_at: SourceTimestamp,
	) -> Result<Self, Self::Error> {
		ClosedStage::apply_metadata_with_access_time(self, metadata, accessed_at)
	}

	fn sync_stage_directory(&self) -> Result<(), Self::Error> {
		ClosedStage::sync_stage_directory(self)
	}
}

#[cfg(test)]
#[path = "../../tests/unit/linux_staging_capabilities.rs"]
mod tests;
