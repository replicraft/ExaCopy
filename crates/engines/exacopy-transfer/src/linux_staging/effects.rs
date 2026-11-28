use exacopy_endpoint::linux_staging::{SourceMetadata, StageReader, StageWriter, StagingDirectory};

use super::StageRequest;

type Reader<'stage, D, E> = <<E as StageEffects<D>>::Writer<'stage> as StageWriter>::Reader;
type AccessTime<D> = <<D as StagingDirectory>::Metadata as SourceMetadata>::Timestamp;

pub(super) trait StageEffects<D: StagingDirectory>: Sized {
	type Writer<'stage>: StageWriter<Error = D::Error, Identity = D::Identity, Metadata = D::Metadata>
	where
		D: 'stage;

	fn create<'stage>(
		&self,
		directory: &'stage D,
		request: StageRequest<'_>,
	) -> Result<Self::Writer<'stage>, D::Error>;
	fn sync_directory(&self, directory: &D) -> Result<(), D::Error>;
	fn write<'stage>(
		&self,
		writer: &mut Self::Writer<'stage>,
		offset: u64,
		bytes: &[u8],
	) -> Result<(), D::Error>
	where
		D: 'stage;
	fn set_len<'stage>(
		&self,
		writer: &mut Self::Writer<'stage>,
		length: u64,
	) -> Result<(), D::Error>
	where
		D: 'stage;
	fn flush<'stage>(&self, writer: &mut Self::Writer<'stage>) -> Result<(), D::Error>
	where
		D: 'stage;
	fn apply_metadata<'stage>(
		&self,
		reader: Reader<'stage, D, Self>,
		metadata: D::Metadata,
		accessed_at: AccessTime<D>,
	) -> Result<Reader<'stage, D, Self>, D::Error>
	where
		D: 'stage;
	fn sync_sealed_stage<'stage>(&self, reader: &Reader<'stage, D, Self>) -> Result<(), D::Error>
	where
		D: 'stage;
}

pub(super) struct OrdinaryEffects;

impl<D: StagingDirectory> StageEffects<D> for OrdinaryEffects {
	type Writer<'stage>
		= D::Writer<'stage>
	where
		D: 'stage;

	fn create<'stage>(
		&self,
		directory: &'stage D,
		request: StageRequest<'_>,
	) -> Result<Self::Writer<'stage>, D::Error> {
		directory.create_file(request.stage_name, request.target, request.binding)
	}

	fn sync_directory(&self, directory: &D) -> Result<(), D::Error> {
		directory.sync_directory()
	}

	fn write<'stage>(
		&self,
		writer: &mut Self::Writer<'stage>,
		offset: u64,
		bytes: &[u8],
	) -> Result<(), D::Error>
	where
		D: 'stage,
	{
		writer.write_all_at(offset, bytes)
	}

	fn set_len<'stage>(
		&self,
		writer: &mut Self::Writer<'stage>,
		length: u64,
	) -> Result<(), D::Error>
	where
		D: 'stage,
	{
		writer.set_len(length)
	}

	fn flush<'stage>(&self, writer: &mut Self::Writer<'stage>) -> Result<(), D::Error>
	where
		D: 'stage,
	{
		writer.flush()
	}

	fn apply_metadata<'stage>(
		&self,
		reader: Reader<'stage, D, Self>,
		metadata: D::Metadata,
		accessed_at: AccessTime<D>,
	) -> Result<Reader<'stage, D, Self>, D::Error>
	where
		D: 'stage,
	{
		reader.apply_metadata_with_access_time(metadata, accessed_at)
	}

	fn sync_sealed_stage<'stage>(&self, reader: &Reader<'stage, D, Self>) -> Result<(), D::Error>
	where
		D: 'stage,
	{
		reader.sync_stage_directory()
	}
}
