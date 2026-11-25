//! Verified fresh-stage transfer over caller-supplied endpoint capabilities.

use exacopy_content::{ContentDigest, copy_and_measure_at, measure_at, validate_stream_input};
use exacopy_endpoint::{ClosedStage, FreshStage, MetadataSource, ReadView, RequiredMetadataStage};

mod error;

#[cfg(test)]
mod tests;

pub use error::StageCopyFailure;

/// The verified private stage or the first failed staging phase.
pub type StageCopyResult<S, R, W> = Result<VerifiedStage<S>, StageCopyFailure<R, W>>;

/// A private stage and the two independently measured digests that agreed.
#[derive(Debug)]
pub struct VerifiedStage<S> {
	stage: S,
	source_digest: ContentDigest,
	stage_digest: ContentDigest,
}

impl<S> VerifiedStage<S> {
	/// Returns the held stage and the measurements in source and read-back order.
	#[must_use]
	pub fn into_parts(self) -> (S, ContentDigest, ContentDigest) {
		(self.stage, self.source_digest, self.stage_digest)
	}
}

/// Copies from a read-only source into a fresh stage and verifies its logical stream.
///
/// Successful verification requires complete sequential writes, a data barrier and
/// writer closure, and independent read-back followed by a final source observation.
/// The stage remains private. Use caller-owned scratch within both endpoints' limits.
///
/// # Errors
/// Reports the first failed admission, transfer, observation or verification.
pub fn copy_fresh<R: ReadView, W: FreshStage>(
	source: &R,
	mut writer: W,
	scratch: &mut [u8],
) -> StageCopyResult<W::Closed, R::Error, W::Error> {
	let length = source.length();
	let stage_length = writer
		.unwritten_length()
		.map_err(StageCopyFailure::InitialStage)?;
	if stage_length != length {
		return Err(StageCopyFailure::ExtentMismatch {
			source_length: length,
			stage_length,
		});
	}
	if scratch.len() > W::MAX_CHUNK_BYTES {
		return Err(StageCopyFailure::ScratchTooLarge {
			length: scratch.len(),
		});
	}
	validate_stream_input(length, scratch.len()).map_err(StageCopyFailure::InvalidInput)?;
	source
		.recheck_observation()
		.map_err(StageCopyFailure::RevalidateSource)?;

	let source_digest = copy_and_measure_at(
		length,
		scratch,
		|offset, bytes| source.read_exact_at(offset, bytes),
		|_, bytes| writer.write_next(bytes),
	)
	.map_err(StageCopyFailure::Copy)?;
	let stage = writer
		.sync_and_close()
		.map_err(StageCopyFailure::CloseStage)?;
	let stage_digest = verify_read_back(&stage, stage_length, source_digest, scratch)?;
	source
		.recheck_observation()
		.map_err(StageCopyFailure::RevalidateSource)?;

	Ok(VerifiedStage {
		stage,
		source_digest,
		stage_digest,
	})
}

/// Admits and installs the required metadata profile around verified fresh staging.
///
/// The original source supplies the required metadata before reads and after
/// independently verified read-back. The resulting capability remains private.
///
/// # Errors
/// Returns copy or verification failures and refuses incomplete metadata or synchronization.
pub fn copy_fresh_with_metadata<R, W>(
	source: &R,
	writer: W,
	scratch: &mut [u8],
) -> StageCopyResult<<W::Closed as RequiredMetadataStage<R>>::Ready, R::Error, W::Error>
where
	R: MetadataSource,
	W: FreshStage,
	W::Closed: RequiredMetadataStage<R>,
{
	source
		.admit_metadata()
		.map_err(StageCopyFailure::AdmitMetadata)?;
	let verified = copy_fresh(source, writer, scratch)?;
	let stage = verified
		.stage
		.apply_metadata(source)
		.map_err(StageCopyFailure::ApplyMetadata)?;
	Ok(VerifiedStage {
		stage,
		source_digest: verified.source_digest,
		stage_digest: verified.stage_digest,
	})
}

/// Independently verifies a closed private stage against a previously measured stream.
/// The caller supplies the bound stage's declared extent and scratch within its adapter limit.
/// # Errors
/// Refuses an unbound or changed reader, an extent mismatch, incomplete reads, or a digest mismatch.
pub fn verify_read_back<R, C: ClosedStage>(
	stage: &C,
	stage_length: u64,
	source_digest: ContentDigest,
	scratch: &mut [u8],
) -> Result<ContentDigest, StageCopyFailure<R, C::Error>> {
	let reader = stage
		.open_read_back()
		.map_err(StageCopyFailure::OpenReadBack)?;
	let read_back_length = reader.length();
	if read_back_length != stage_length {
		return Err(StageCopyFailure::ReadBackExtentMismatch {
			stage_length,
			read_back_length,
		});
	}
	let stage_digest = measure_at(stage_length, scratch, |offset, bytes| {
		reader.read_exact_at(offset, bytes)
	})
	.map_err(StageCopyFailure::ReadBack)?;
	reader
		.recheck_observation()
		.map_err(StageCopyFailure::RevalidateReadBack)?;
	if source_digest != stage_digest {
		return Err(StageCopyFailure::DigestMismatch {
			source_digest,
			stage_digest,
		});
	}
	Ok(stage_digest)
}
