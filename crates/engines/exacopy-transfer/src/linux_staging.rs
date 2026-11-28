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

mod effects;
mod error;

#[cfg(test)]
mod tests;

use effects::OrdinaryEffects;
pub(crate) use effects::{GuardedEffects, StageEffects};
pub use error::{StageCopyError, StageFailure};

const SPECIAL_MODE_BITS: u32 = 0o7000;

type StageResult<T, Source, Writer> = Result<
	T,
	StageCopyError<<Source as exacopy_endpoint::ReadView>::Error, <Writer as StageWriter>::Error>,
>;
type VerifiedResult<Source, Writer> =
	StageResult<VerifiedStage<<Writer as StageWriter>::Reader>, Source, Writer>;
type PreparedStage<Source, Writer> = Result<
	(<Writer as StageWriter>::Reader, ObservedStreams),
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
	streams: ObservedStreams,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ObservedStreams {
	pub(crate) source_length: u64,
	pub(crate) source_digest: ContentDigest,
	pub(crate) stage_length: u64,
	pub(crate) stage_digest: ContentDigest,
}

impl<Reader: StageReader> VerifiedStage<Reader> {
	/// The verified BLAKE3 digest of the observed logical stream.
	#[must_use]
	pub const fn digest(&self) -> ContentDigest {
		self.streams.source_digest
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
		(self.stage, self.session, self.streams.source_digest)
	}

	pub(crate) const fn observed_streams(&self) -> ObservedStreams {
		self.streams
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
		&mut dyn StageRecords<S::Identity, S::Error, <D::Writer<'stage> as StageWriter>::Error>,
	>,
) -> VerifiedResult<S, D::Writer<'stage>>
where
	S: StagingSource,
	D: StagingDirectory<Identity = S::Identity, Metadata = S::Metadata>,
{
	stage_verified_with(
		source,
		directory,
		request,
		scratch,
		records,
		&OrdinaryEffects,
	)
}

pub(crate) fn stage_verified_with<'stage, S, D, E>(
	source: &S,
	directory: &'stage D,
	request: StageRequest<'_>,
	scratch: &mut [u8],
	records: Option<
		&mut dyn StageRecords<S::Identity, S::Error, <E::Writer<'stage> as StageWriter>::Error>,
	>,
	effects: &E,
) -> VerifiedResult<S, E::Writer<'stage>>
where
	S: StagingSource,
	D: StagingDirectory<Identity = S::Identity, Metadata = S::Metadata>,
	E: StageEffects<D>,
{
	let mut session = CopySession::new(request.binding);
	let result = prepare(
		source,
		directory,
		request,
		scratch,
		&mut session,
		records,
		effects,
	);
	match result {
		Ok((stage, streams)) => Ok(VerifiedStage {
			stage,
			session,
			streams,
		}),
		Err(failure) => Err(StageCopyError {
			phase: session.phase(),
			failure,
		}),
	}
}

fn prepare<'stage, S, D, E>(
	source: &S,
	directory: &'stage D,
	request: StageRequest<'_>,
	scratch: &mut [u8],
	session: &mut CopySession,
	records: Option<
		&mut dyn StageRecords<S::Identity, S::Error, <E::Writer<'stage> as StageWriter>::Error>,
	>,
	effects: &E,
) -> PreparedStage<S, E::Writer<'stage>>
where
	S: StagingSource,
	D: StagingDirectory<Identity = S::Identity, Metadata = S::Metadata>,
	E: StageEffects<D>,
{
	let source_length = source.length();
	validate_stream_input(source_length, scratch.len()).map_err(StageFailure::Input)?;
	check_source(source)?;
	let mut writable = effects
		.create(directory, request)
		.map_err(StageFailure::Stage)?;
	if writable.identity() == source.identity() {
		return Err(StageFailure::Alias);
	}
	writable
		.check_ownership(source.metadata())
		.map_err(StageFailure::Stage)?;
	let checkpoints = if let Some(records) = records {
		effects
			.sync_directory(directory)
			.map_err(StageFailure::Stage)?;
		let measurement = records.begin(writable.identity())?;
		Some((records, measurement))
	} else {
		None
	};
	begin_stage_reads(session, request.binding)?;

	let source_digest = if let Some((records, measurement)) = checkpoints {
		copy_with_checkpoints::<S, D, E>(
			source,
			source_length,
			&mut writable,
			scratch,
			records,
			measurement,
			effects,
		)?
	} else {
		copy_and_measure_at(
			source_length,
			scratch,
			|offset, bytes| source.read_exact_at(offset, bytes),
			|offset, bytes| effects.write(&mut writable, offset, bytes),
		)
		.map_err(StageFailure::Copy)?
	};
	flush_written_stage_with(
		&mut writable,
		source_length,
		session,
		request.binding,
		|writer, length| effects.set_len(writer, length),
		|writer| effects.flush(writer),
	)?;
	let stage = writable.close_writes().map_err(StageFailure::Stage)?;
	let (stage_length, stage_digest) = verify_stage_readback(
		&stage,
		source_length,
		source_digest,
		scratch,
		session,
		request.binding,
	)?;
	let stage = complete_stage_metadata_with(
		stage,
		source,
		source.metadata().accessed_at(),
		session,
		request.binding,
		|reader, metadata, accessed_at| effects.apply_metadata(reader, metadata, accessed_at),
		|reader| effects.sync_sealed_stage(reader),
	)?;
	Ok((
		stage,
		ObservedStreams {
			source_length,
			source_digest,
			stage_length,
			stage_digest,
		},
	))
}

fn copy_with_checkpoints<'stage, S, D, E>(
	source: &S,
	length: u64,
	writer: &mut E::Writer<'stage>,
	scratch: &mut [u8],
	records: &mut dyn StageRecords<S::Identity, S::Error, D::Error>,
	measurement: SourceMeasurementId,
	effects: &E,
) -> Result<ContentDigest, StageFailure<S::Error, D::Error>>
where
	S: StagingSource,
	D: StagingDirectory<Identity = S::Identity, Metadata = S::Metadata> + 'stage,
	E: StageEffects<D>,
{
	copy_and_checkpoint_at(
		length,
		scratch,
		|offset, bytes| source.read_exact_at(offset, bytes),
		|offset, bytes, range| {
			effects
				.write(writer, offset, bytes)
				.map_err(|source| StageFailure::Copy(CopyMeasureError::Write { offset, source }))?;
			if let Some(range) = range {
				source.recheck_metadata().map_err(StageFailure::Source)?;
				effects.flush(writer).map_err(StageFailure::Stage)?;
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
	flush_written_stage_with(
		writable,
		length,
		session,
		binding,
		StageWriter::set_len,
		StageWriter::flush,
	)
}

fn flush_written_stage_with<R, W: StageWriter>(
	writable: &mut W,
	length: u64,
	session: &mut CopySession,
	binding: CopyBinding,
	set_len: impl FnOnce(&mut W, u64) -> Result<(), W::Error>,
	flush: impl FnOnce(&mut W) -> Result<(), W::Error>,
) -> Result<(), StageFailure<R, W::Error>> {
	set_len(writable, length).map_err(StageFailure::Stage)?;
	observe(session, binding, CopyEvent::WritersJoined)?;
	flush(writable).map_err(StageFailure::Stage)?;
	observe(session, binding, CopyEvent::DataFlushed)
}

pub(crate) fn verify_stage_readback<R, S: StageReader>(
	stage: &S,
	source_length: u64,
	source_digest: ContentDigest,
	scratch: &mut [u8],
	session: &mut CopySession,
	binding: CopyBinding,
) -> Result<(u64, ContentDigest), StageFailure<R, S::Error>> {
	let stage_length = stage.length();
	if stage_length != source_length {
		return Err(StageFailure::LengthMismatch {
			expected: source_length,
			actual: stage_length,
		});
	}
	let stage_digest = measure_at(stage_length, scratch, |offset, bytes| {
		stage.read_exact_at(offset, bytes)
	})
	.map_err(StageFailure::Readback)?;
	if stage_digest != source_digest {
		return Err(StageFailure::DigestMismatch);
	}
	observe(session, binding, CopyEvent::ReadbackVerified)?;
	Ok((stage_length, stage_digest))
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
	complete_stage_metadata_with(
		stage,
		source,
		accessed_at,
		session,
		binding,
		StageReader::apply_metadata_with_access_time,
		StageReader::sync_stage_directory,
	)
}

fn complete_stage_metadata_with<S, R>(
	stage: R,
	source: &S,
	accessed_at: <S::Metadata as SourceMetadata>::Timestamp,
	session: &mut CopySession,
	binding: CopyBinding,
	apply: impl FnOnce(
		R,
		S::Metadata,
		<S::Metadata as SourceMetadata>::Timestamp,
	) -> Result<R, R::Error>,
	sync: impl FnOnce(&R) -> Result<(), R::Error>,
) -> Result<R, StageFailure<S::Error, R::Error>>
where
	S: StagingSource,
	R: StageReader<Identity = S::Identity, Metadata = S::Metadata>,
{
	check_source(source)?;
	let stage = apply(stage, source.metadata(), accessed_at).map_err(StageFailure::Stage)?;
	sync(&stage).map_err(StageFailure::Stage)?;
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
