use crate::macos::replay::DarwinJournalReplay;
use exacopy_content::{
	ContentDigest, MeasureError, StreamInputError, measure_at, validate_stream_input,
};
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DarwinFileIdentity, DarwinMetadataRecorded, DarwinPhaseError, DarwinRequiredMetadata,
	DarwinStageObservation, DarwinStreamEvidence, DarwinVerificationRecorded,
};

use super::capabilities::{InspectionInventory, InspectionStageReader, StageMetadata};

#[derive(Debug)]
pub(super) enum ReadBackError<E> {
	MissingVerification,
	StageBinding,
	Phase(DarwinPhaseError),
	ScratchTooLarge { length: usize },
	Input(StreamInputError),
	Platform(E),
	Read(MeasureError<E>),
	DigestMismatch,
	InitialMetadataMismatch,
	FinalMetadataMismatch,
}

pub(super) fn verify<I: InspectionInventory>(
	replay: &DarwinJournalReplay,
	prepared: Option<DarwinStageObservation<'_>>,
	names: &I,
	scratch: &mut [u8],
) -> Result<ContentDigest, ReadBackError<I::Error>> {
	let prepared = prepared.ok_or(ReadBackError::MissingVerification)?;
	let verification = replay
		.frame(FrameKind::VerificationRecorded)
		.ok_or(ReadBackError::MissingVerification)
		.and_then(|frame| {
			DarwinVerificationRecorded::from_frame(frame).map_err(ReadBackError::Phase)
		})?;
	let expected = verification.stage();
	let metadata = replay
		.frame(FrameKind::MetadataRecorded)
		.map(DarwinMetadataRecorded::from_frame)
		.transpose()
		.map_err(ReadBackError::Phase)?
		.map(|record| record.metadata());
	verify_bound_stage(names, prepared.directory, expected, metadata, scratch)
}

fn verify_bound_stage<I: InspectionInventory>(
	names: &I,
	directory: DarwinFileIdentity,
	expected: DarwinStreamEvidence,
	metadata: Option<DarwinRequiredMetadata>,
	scratch: &mut [u8],
) -> Result<ContentDigest, ReadBackError<I::Error>> {
	let length = expected.length.get();
	if scratch.len() > I::MAX_READ_BYTES {
		return Err(ReadBackError::ScratchTooLarge {
			length: scratch.len(),
		});
	}
	validate_stream_input(length, scratch.len()).map_err(ReadBackError::Input)?;

	let stage = names.stage().ok_or(ReadBackError::StageBinding)?;
	if names.stage_directory_identity() != Some(directory)
		|| stage.identity != expected.identity
		|| stage.length != length
	{
		return Err(ReadBackError::StageBinding);
	}
	let reader = names
		.open_stage_read_back(stage.held)
		.map_err(ReadBackError::Platform)?;
	if metadata.is_some_and(|expected| !matches_metadata(reader.initial_metadata(), expected)) {
		return Err(ReadBackError::InitialMetadataMismatch);
	}
	let digest = measure_at(length, scratch, |offset, chunk| {
		reader.read_exact_at(offset, chunk)
	})
	.map_err(ReadBackError::Read)?;
	let final_metadata = reader.revalidate().map_err(ReadBackError::Platform)?;
	if digest.as_bytes() != expected.digest.as_bytes() {
		return Err(ReadBackError::DigestMismatch);
	}
	if metadata.is_some_and(|expected| !matches_metadata(final_metadata, expected)) {
		return Err(ReadBackError::FinalMetadataMismatch);
	}
	Ok(digest)
}

fn matches_metadata(observed: StageMetadata, expected: DarwinRequiredMetadata) -> bool {
	let permissions = expected.permissions();
	observed.uid == permissions.owner().get()
		&& observed.gid == permissions.group()
		&& observed.mode == permissions.mode()
		&& observed.atime
			== (
				expected.accessed_at.seconds(),
				expected.accessed_at.nanoseconds(),
			)
		&& observed.mtime
			== (
				expected.modified_at.seconds(),
				expected.modified_at.nanoseconds(),
			)
}
