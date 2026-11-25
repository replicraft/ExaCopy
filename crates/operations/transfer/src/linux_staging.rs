//! Verified staging protocol for Linux's synchronous local preservation profile.

use exacopy_content::{
	ContentDigest, CopyMeasureError, RangeMeasurement, copy_and_checkpoint_at, copy_and_measure_at,
	measure_at, validate_stream_input,
};
use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_staging::{
	ExtendedAttributes, SourceMetadata, StageReader, StageWriter, StagingDirectory, StagingSource,
};
use exacopy_journal::SourceMeasurementId;
use exacopy_model::{CopyBinding, CopyEffect, CopyEvent, CopyPhase, CopySession};

mod error;

#[cfg(test)]
mod tests;

pub use error::{StageCopyError, StageFailure};

const SPECIAL_MODE_BITS: u32 = 0o7000;

type StageResult<T, Source, Writer> = Result<
	T,
	StageCopyError<<Source as exacopy_endpoint::ReadView>::Error, <Writer as StageWriter>::Error>,
>;
type PreparedStage<Source, Writer> = Result<
	(<Writer as StageWriter>::Reader, ContentDigest),
	StageFailure<<Source as exacopy_endpoint::ReadView>::Error, <Writer as StageWriter>::Error>,
>;

/// The reserved names and attempt identity for one private file.
#[derive(Debug, Clone, Copy)]
pub struct StageRequest<'name> {
	/// The exclusive file name inside the owned stage directory.
	pub stage_name: UnixComponent<'name>,
	/// The intended name in the held destination root.
	pub target: UnixComponent<'name>,
	/// The job, entry, epoch, and stage binding allocated by the coordinator.
	pub binding: CopyBinding,
}

/// Durable preparation and bounded range evidence for a recoverable private stage.
pub trait StageRecords<Identity, ReadError, StageError> {
	/// Synchronizes the initial preparation record bound to the observed stage.
	/// # Errors
	/// Fails if the preparation record cannot be encoded or durably recorded.
	fn begin(
		&mut self,
		stage: Identity,
	) -> Result<SourceMeasurementId, StageFailure<ReadError, StageError>>;

	/// Synchronizes evidence of a range after the stage's data barrier.
	/// # Errors
	/// Fails if the checkpoint cannot be encoded or durably recorded.
	fn record(
		&mut self,
		measurement: SourceMeasurementId,
		range: RangeMeasurement,
	) -> Result<(), StageFailure<ReadError, StageError>>;
}

/// A private stage with independently verified content and completed metadata.
#[derive(Debug)]
pub struct VerifiedStage<Reader> {
	stage: Reader,
	session: CopySession,
	digest: ContentDigest,
}

impl<Reader: StageReader> VerifiedStage<Reader> {
	/// The verified BLAKE3 digest of the observed logical stream.
	#[must_use]
	pub const fn digest(&self) -> ContentDigest {
		self.digest
	}

	/// The verified logical length.
	#[must_use]
	pub fn length(&self) -> u64 {
		self.stage.length()
	}

	/// The physical identity of the pinned stage.
	#[must_use]
	pub fn identity(&self) -> Reader::Identity {
		self.stage.identity()
	}

	/// The model phase backed by observations made during this attempt.
	#[must_use]
	pub const fn phase(&self) -> CopyPhase {
		self.session.phase()
	}

	/// Transfers the pinned stage, its decision session and the verified digest to the coordinator.
	#[must_use]
	pub fn into_parts(self) -> (Reader, CopySession, ContentDigest) {
		(self.stage, self.session, self.digest)
	}
}

/// Copies a live observed stream into a private, independently verified stage.
///
/// The caller supplies held capabilities and a unique attempt binding. An optional recorder
/// enables recoverable range checkpoints. The bounded scratch buffer is reused for read-back.
/// # Errors
/// Reports the last model phase and cause. An allocated stage remains private for inspection.
pub fn stage_verified<'stage, S, D>(
	source: &S,
	directory: &'stage D,
	request: StageRequest<'_>,
	scratch: &mut [u8],
	records: Option<
		&mut dyn StageRecords<S::Identity, S::Error, <D::Writer as StageWriter>::Error>,
	>,
) -> StageResult<VerifiedStage<<D::Writer as StageWriter>::Reader>, S, D::Writer>
where
	S: StagingSource,
	D: StagingDirectory<'stage>,
	D::Writer: StageWriter<Identity = S::Identity, Metadata = S::Metadata>,
{
	let mut session = CopySession::new(request.binding);
	let result = prepare(source, directory, request, scratch, &mut session, records);
	match result {
		Ok((stage, digest)) => Ok(VerifiedStage {
			stage,
			session,
			digest,
		}),
		Err(failure) => Err(StageCopyError {
			phase: session.phase(),
			failure,
		}),
	}
}

fn prepare<'stage, S, D>(
	source: &S,
	directory: &'stage D,
	request: StageRequest<'_>,
	scratch: &mut [u8],
	session: &mut CopySession,
	records: Option<
		&mut dyn StageRecords<S::Identity, S::Error, <D::Writer as StageWriter>::Error>,
	>,
) -> PreparedStage<S, D::Writer>
where
	S: StagingSource,
	D: StagingDirectory<'stage>,
	D::Writer: StageWriter<Identity = S::Identity, Metadata = S::Metadata>,
{
	validate_stream_input(source.length(), scratch.len()).map_err(StageFailure::Input)?;
	check_source(source)?;
	let mut writable = directory
		.create_file(request.stage_name, request.target, request.binding)
		.map_err(StageFailure::Stage)?;
	if writable.identity() == source.identity() {
		return Err(StageFailure::Alias);
	}
	writable
		.check_ownership(source.metadata())
		.map_err(StageFailure::Stage)?;
	let checkpoints = if let Some(records) = records {
		directory.sync_directory().map_err(StageFailure::Stage)?;
		let measurement = records.begin(writable.identity())?;
		Some((records, measurement))
	} else {
		None
	};
	begin_stage_reads(session, request.binding)?;

	let source_digest = if let Some((records, measurement)) = checkpoints {
		copy_with_checkpoints(source, &mut writable, scratch, records, measurement)?
	} else {
		copy_and_measure_at(
			source.length(),
			scratch,
			|offset, bytes| source.read_exact_at(offset, bytes),
			|offset, bytes| writable.write_all_at(offset, bytes),
		)
		.map_err(StageFailure::Copy)?
	};
	flush_written_stage(&mut writable, source.length(), session, request.binding)?;
	let stage = writable.close_writes().map_err(StageFailure::Stage)?;
	verify_stage_readback(
		&stage,
		source.length(),
		source_digest,
		scratch,
		session,
		request.binding,
	)?;
	let stage = complete_stage_metadata(
		stage,
		source,
		source.metadata().accessed_at(),
		session,
		request.binding,
	)?;
	Ok((stage, source_digest))
}

fn copy_with_checkpoints<S, W>(
	source: &S,
	writer: &mut W,
	scratch: &mut [u8],
	records: &mut dyn StageRecords<S::Identity, S::Error, W::Error>,
	measurement: SourceMeasurementId,
) -> Result<ContentDigest, StageFailure<S::Error, W::Error>>
where
	S: StagingSource,
	W: StageWriter<Identity = S::Identity, Metadata = S::Metadata>,
{
	copy_and_checkpoint_at(
		source.length(),
		scratch,
		|offset, bytes| source.read_exact_at(offset, bytes),
		|offset, bytes, range| {
			writer
				.write_all_at(offset, bytes)
				.map_err(|source| StageFailure::Copy(CopyMeasureError::Write { offset, source }))?;
			if let Some(range) = range {
				source.recheck_metadata().map_err(StageFailure::Source)?;
				writer.flush().map_err(StageFailure::Stage)?;
				records.record(measurement, range)?;
			}
			Ok(())
		},
	)
	.map_err(|error| match error {
		CopyMeasureError::InvalidInput(error) => StageFailure::Input(error),
		CopyMeasureError::Read { offset, source } => {
			StageFailure::Copy(CopyMeasureError::Read { offset, source })
		}
		CopyMeasureError::Write { source, .. } => source,
	})
}

pub(crate) fn begin_stage_reads<R, W>(
	session: &mut CopySession,
	binding: CopyBinding,
) -> Result<(), StageFailure<R, W>> {
	match session.apply(binding, CopyEvent::StagePrepared)? {
		Some(CopyEffect::ReadSource(read)) if read.binding() == binding => Ok(()),
		_ => Err(StageFailure::UnexpectedEffect),
	}
}

pub(crate) fn flush_written_stage<R, W: StageWriter>(
	writable: &mut W,
	length: u64,
	session: &mut CopySession,
	binding: CopyBinding,
) -> Result<(), StageFailure<R, W::Error>> {
	writable.set_len(length).map_err(StageFailure::Stage)?;
	observe(session, binding, CopyEvent::WritersJoined)?;
	writable.flush().map_err(StageFailure::Stage)?;
	observe(session, binding, CopyEvent::DataFlushed)
}

pub(crate) fn verify_stage_readback<R, S: StageReader>(
	stage: &S,
	source_length: u64,
	source_digest: ContentDigest,
	scratch: &mut [u8],
	session: &mut CopySession,
	binding: CopyBinding,
) -> Result<(), StageFailure<R, S::Error>> {
	if stage.length() != source_length {
		return Err(StageFailure::LengthMismatch {
			expected: source_length,
			actual: stage.length(),
		});
	}
	let stage_digest = measure_at(stage.length(), scratch, |offset, bytes| {
		stage.read_exact_at(offset, bytes)
	})
	.map_err(StageFailure::Readback)?;
	if stage_digest != source_digest {
		return Err(StageFailure::DigestMismatch);
	}
	observe(session, binding, CopyEvent::ReadbackVerified)
}

pub(crate) fn complete_stage_metadata<S, R>(
	stage: R,
	source: &S,
	accessed_at: <S::Metadata as SourceMetadata>::Timestamp,
	session: &mut CopySession,
	binding: CopyBinding,
) -> Result<R, StageFailure<S::Error, R::Error>>
where
	S: StagingSource,
	R: StageReader<Identity = S::Identity, Metadata = S::Metadata>,
{
	check_source(source)?;
	let stage = stage
		.apply_metadata_with_access_time(source.metadata(), accessed_at)
		.map_err(StageFailure::Stage)?;
	stage.sync_stage_directory().map_err(StageFailure::Stage)?;
	check_source(source)?;
	observe(session, binding, CopyEvent::MetadataReady)?;
	observe(session, binding, CopyEvent::StageSealed)?;
	Ok(stage)
}

pub(crate) fn check_source<S: StagingSource, W>(
	source: &S,
) -> Result<(), StageFailure<S::Error, W>> {
	let attributes = source.extended_attributes().map_err(StageFailure::Source)?;
	source.recheck_observation().map_err(StageFailure::Source)?;
	if attributes != ExtendedAttributes::NoneVisible {
		return Err(StageFailure::SourceAttributes(attributes));
	}
	let mode = source.metadata().mode();
	if mode & SPECIAL_MODE_BITS != 0 {
		return Err(StageFailure::UnsupportedSourceMode { mode });
	}
	Ok(())
}

pub(crate) fn observe<R, W>(
	session: &mut CopySession,
	binding: CopyBinding,
	event: CopyEvent,
) -> Result<(), StageFailure<R, W>> {
	if session.apply(binding, event)?.is_some() {
		return Err(StageFailure::UnexpectedEffect);
	}
	Ok(())
}
