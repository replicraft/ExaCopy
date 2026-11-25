use exacopy_endpoint::{
	ClosedStage as ClosedStageCapability, FreshStage, MetadataSource, RequiredMetadataStage,
};

use super::super::ManagedRegularFile;
use super::{
	ClosedStage, MAX_STAGE_IO_BYTES, MetadataReadyStage, StageError, StageReader, WriteStage,
};

impl<'stage> FreshStage for WriteStage<'stage> {
	type Error = StageError;
	type Closed = ClosedStage<'stage>;
	const MAX_CHUNK_BYTES: usize = MAX_STAGE_IO_BYTES;

	fn unwritten_length(&self) -> Result<u64, Self::Error> {
		WriteStage::unwritten_length(self)
	}

	fn write_next(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		WriteStage::write_next(self, buffer)
	}

	fn sync_and_close(self) -> Result<Self::Closed, Self::Error> {
		self.flush_and_close()
	}
}

impl ClosedStageCapability for ClosedStage<'_> {
	type Error = StageError;
	type Reader<'stage>
		= StageReader<'stage>
	where
		Self: 'stage;

	fn open_read_back(&self) -> Result<Self::Reader<'_>, Self::Error> {
		ClosedStage::open_read_back(self)
	}
}

impl MetadataSource for ManagedRegularFile<'_> {
	fn admit_metadata(&self) -> Result<(), Self::Error> {
		self.check_basic_metadata().map(|_| ())
	}
}

impl<'stage> RequiredMetadataStage<ManagedRegularFile<'_>> for ClosedStage<'stage> {
	type Ready = MetadataReadyStage<'stage>;

	fn apply_metadata(self, source: &ManagedRegularFile<'_>) -> Result<Self::Ready, Self::Error> {
		self.apply_basic_metadata(source)
	}
}
