//! Verified content staging in owner-managed local APFS directories.

use exacopy_content::{ContentDigest, copy_and_measure_at, measure_at, validate_stream_input};
use exacopy_model::CopyBinding;
use exacopy_platform::macos::staging::{
	ClosedStage, MAX_STAGE_IO_BYTES, MetadataReadyStage, StageIdentity, WriteStage,
};
use exacopy_platform::macos::{BasicMetadata, ManagedRegularFile};

mod error;
pub mod job;
pub mod plan;
pub mod receipt;

#[cfg(test)]
mod tests;

pub use error::{StageTransferError, StageTransferFailure};

/// Owns verified data and synchronized basic metadata for the same private stage.
#[derive(Debug)]
pub struct VerifiedBasicStage<'stage> {
	stage: MetadataReadyStage<'stage>,
	digest: ContentDigest,
}

impl VerifiedBasicStage<'_> {
	/// Returns the binding of the stage that was independently verified.
	#[must_use]
	pub fn binding(&self) -> CopyBinding {
		self.stage.binding()
	}

	/// Returns the selected metadata read back after the file barrier.
	#[must_use]
	pub fn metadata(&self) -> BasicMetadata {
		self.stage.metadata()
	}

	/// Returns the BLAKE3-256 digest measured independently from the private stage.
	#[must_use]
	pub fn digest(&self) -> ContentDigest {
		self.digest
	}
}

/// Verifies a private copy and applies the strict basic metadata of that same source.
/// Metadata admission precedes payload reads. Metadata application follows independent
/// stage read-back and writer closure. The verified stage remains private.
/// # Errors
/// Refuses unsupported metadata, failed verification or incomplete persistence.
/// The error identifies the private stage retained for reconciliation.
pub fn copy_with_basic_metadata<'stage>(
	source: &ManagedRegularFile<'_>,
	writer: WriteStage<'stage>,
	scratch: &mut [u8],
) -> Result<VerifiedBasicStage<'stage>, StageTransferError> {
	let identity = writer.identity();
	source.check_basic_metadata().map_err(|error| {
		StageTransferError::new(identity, StageTransferFailure::AdmitMetadata(error))
	})?;
	let verified = copy_verified_stage(source, writer, scratch)?;
	let stage = verified
		.stage
		.apply_basic_metadata(source)
		.map_err(|error| {
			StageTransferError::new(identity, StageTransferFailure::ApplyMetadata(error))
		})?;
	Ok(VerifiedBasicStage {
		stage,
		digest: verified.digest,
	})
}

/// Owns the closed private stage and the digest independently read from it.
///
/// This evidence covers the unnamed data stream. Source observations remain live,
/// and the stage read-back may be served by the filesystem cache.
#[derive(Debug)]
pub struct VerifiedStage<'stage> {
	stage: ClosedStage<'stage>,
	digest: ContentDigest,
}

impl VerifiedStage<'_> {
	/// Returns the identity of the verified private stage.
	#[must_use]
	pub fn identity(&self) -> StageIdentity {
		self.stage.identity()
	}

	/// Returns the transaction binding allocated before the stage was created.
	#[must_use]
	pub fn binding(&self) -> CopyBinding {
		self.stage.binding()
	}

	/// Returns the verified extent of the unnamed stream in bytes.
	#[must_use]
	pub fn length(&self) -> u64 {
		self.stage.length()
	}

	/// Reports whether the verified stream was empty.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.stage.is_empty()
	}

	/// Returns the BLAKE3-256 digest independently measured from the private stage.
	#[must_use]
	pub fn digest(&self) -> ContentDigest {
		self.digest
	}
}

/// Copies the source into a fresh private stage and verifies the entire unnamed stream.
///
/// The supplied writer fixes the private stage identity and extent. The stream uses
/// only the caller's scratch space, bounded by the native 1 MiB chunk limit. An
/// independent reader opens only after the stage passes F_FULLFSYNC and the writer
/// closes. Successful read-back and a final source observation produce content evidence.
///
/// # Errors
/// Returns the exact stage identity with a typed admission, I/O, identity or digest
/// failure. Every failure consumes the writer and retains the private entry for
/// reconciliation.
pub fn copy_verified_stage<'stage>(
	source: &ManagedRegularFile<'_>,
	mut stage: WriteStage<'stage>,
	scratch: &mut [u8],
) -> Result<VerifiedStage<'stage>, StageTransferError> {
	let identity = stage.identity();
	let failure = |failure| StageTransferError::new(identity, failure);
	let length = source.length();
	let stage_length = stage
		.unwritten_length()
		.map_err(StageTransferFailure::InitialStage)
		.map_err(failure)?;
	if stage_length != length {
		return Err(failure(StageTransferFailure::ExtentMismatch {
			source_length: length,
			stage_length,
		}));
	}
	if scratch.len() > MAX_STAGE_IO_BYTES {
		return Err(failure(StageTransferFailure::ScratchTooLarge {
			length: scratch.len(),
		}));
	}
	validate_stream_input(length, scratch.len())
		.map_err(StageTransferFailure::InvalidInput)
		.map_err(failure)?;
	source
		.revalidate()
		.map_err(StageTransferFailure::RevalidateSource)
		.map_err(failure)?;

	let source_digest = copy_and_measure_at(
		length,
		scratch,
		|offset, bytes| source.read_exact_at(offset, bytes),
		|_, bytes| stage.write_next(bytes),
	)
	.map_err(StageTransferFailure::Copy)
	.map_err(failure)?;
	let stage = stage
		.flush_and_close()
		.map_err(StageTransferFailure::CloseStage)
		.map_err(failure)?;
	let digest = verify_read_back(&stage, source_digest, scratch).map_err(failure)?;
	source
		.revalidate()
		.map_err(StageTransferFailure::RevalidateSource)
		.map_err(failure)?;

	Ok(VerifiedStage { stage, digest })
}

fn verify_read_back(
	stage: &ClosedStage<'_>,
	source_digest: ContentDigest,
	scratch: &mut [u8],
) -> Result<ContentDigest, StageTransferFailure> {
	let reader = stage
		.open_read_back()
		.map_err(StageTransferFailure::OpenReadBack)?;
	let stage_digest = measure_at(stage.length(), scratch, |offset, bytes| {
		reader.read_exact_at(offset, bytes)
	})
	.map_err(StageTransferFailure::ReadBack)?;
	reader
		.revalidate()
		.map_err(StageTransferFailure::RevalidateReadBack)?;
	if source_digest != stage_digest {
		return Err(StageTransferFailure::DigestMismatch {
			source_digest,
			stage_digest,
		});
	}
	Ok(stage_digest)
}
