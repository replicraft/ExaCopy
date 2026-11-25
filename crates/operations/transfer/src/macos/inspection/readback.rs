use exacopy_content::{ContentDigest, measure_at, validate_stream_input};
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DarwinMetadataRecorded, DarwinRequiredMetadata, DarwinStageObservation,
	DarwinVerificationRecorded,
};
use exacopy_platform::macos::BasicMetadata;
use exacopy_platform::macos::staging::MAX_STAGE_IO_BYTES;
use exacopy_platform::macos::staging::jobs::RecoveryInventory;

use super::{DarwinJournalReplay, DarwinStageReadBackError};
use crate::macos::job::native_identity;

pub(super) fn verify(
	replay: &DarwinJournalReplay,
	prepared: Option<DarwinStageObservation<'_>>,
	names: &RecoveryInventory<'_>,
	scratch: &mut [u8],
) -> Result<ContentDigest, DarwinStageReadBackError> {
	let prepared = prepared.ok_or(DarwinStageReadBackError::MissingVerification)?;
	let verification = replay
		.frame(FrameKind::VerificationRecorded)
		.ok_or(DarwinStageReadBackError::MissingVerification)
		.and_then(|frame| {
			DarwinVerificationRecorded::from_frame(frame).map_err(DarwinStageReadBackError::Phase)
		})?;
	let expected = verification.stage();
	let metadata = replay
		.frame(FrameKind::MetadataRecorded)
		.map(DarwinMetadataRecorded::from_frame)
		.transpose()
		.map_err(DarwinStageReadBackError::Phase)?
		.map(|record| record.metadata());
	let length = expected.length.get();
	if scratch.len() > MAX_STAGE_IO_BYTES {
		return Err(DarwinStageReadBackError::ScratchTooLarge {
			length: scratch.len(),
		});
	}
	validate_stream_input(length, scratch.len()).map_err(DarwinStageReadBackError::Input)?;

	let stage = names
		.stage()
		.ok_or(DarwinStageReadBackError::StageBinding)?;
	if names
		.stage_directory_identity()
		.and_then(|id| native_identity(id).ok())
		!= Some(prepared.directory)
		|| native_identity(stage.identity()).ok() != Some(expected.identity)
		|| stage.length() != length
	{
		return Err(DarwinStageReadBackError::StageBinding);
	}
	let reader = names
		.open_stage_read_back(stage)
		.map_err(DarwinStageReadBackError::Platform)?;
	if metadata.is_some_and(|expected| !matches_metadata(reader.initial_metadata(), expected)) {
		return Err(DarwinStageReadBackError::InitialMetadataMismatch);
	}
	let digest = measure_at(length, scratch, |offset, chunk| {
		reader.read_exact_at(offset, chunk)
	})
	.map_err(DarwinStageReadBackError::Read)?;
	let final_metadata = reader
		.revalidate()
		.map_err(DarwinStageReadBackError::Platform)?;
	if digest.as_bytes() != expected.digest.as_bytes() {
		return Err(DarwinStageReadBackError::DigestMismatch);
	}
	if metadata.is_some_and(|expected| !matches_metadata(final_metadata, expected)) {
		return Err(DarwinStageReadBackError::FinalMetadataMismatch);
	}
	Ok(digest)
}

fn matches_metadata(observed: BasicMetadata, expected: DarwinRequiredMetadata) -> bool {
	let permissions = expected.permissions();
	observed.uid() == permissions.owner().get()
		&& observed.gid() == permissions.group()
		&& observed.mode() == permissions.mode()
		&& observed.atime().seconds() == expected.accessed_at.seconds()
		&& observed.atime().nanoseconds() == expected.accessed_at.nanoseconds()
		&& observed.mtime().seconds() == expected.modified_at.seconds()
		&& observed.mtime().nanoseconds() == expected.modified_at.nanoseconds()
}
