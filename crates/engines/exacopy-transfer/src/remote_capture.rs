//! Fresh, live-observed capture into an exclusively held private stage.

use std::future::Future;
use std::num::{NonZeroU64, NonZeroUsize};

use exacopy_content::{ContentDigest, StreamInputError, measure_at, validate_stream_input};
use exacopy_endpoint::{ClosedStage, FreshStage, ReadView};

mod error;
#[cfg(test)]
mod tests;

pub use error::{CaptureError, StageStep};

const CHECKPOINT_BYTES: NonZeroU64 =
	NonZeroU64::new(64 * 1024 * 1024).expect("the fixed checkpoint interval must be nonzero");
const MAX_CHECKPOINTS: u16 = 4096;

/// A caller-assigned identifier for one held live read pass.
///
/// A reopen or connection-generation change needs a fresh epoch before another
/// pass. This identifies a capture attempt and carries no stable file identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SourceEpoch(NonZeroU64);

impl SourceEpoch {
	/// Wraps the caller's nonzero identifier for a fresh held read pass.
	#[must_use]
	pub const fn new(id: NonZeroU64) -> Self {
		Self(id)
	}

	/// Returns the pass identifier for comparison or checkpoint binding.
	#[must_use]
	pub const fn get(self) -> u64 {
		self.0.get()
	}
}

/// A live read-only stream on one held handle and connection generation.
///
/// Implementations must fail on unconfirmed or stale completions. They may
/// complete short reads on this handle within their own bounded request policy.
/// The adapter cannot retry a call by transparently reopening the source.
pub trait CapturedReadAt {
	/// Adapter's error while reading or checking the captured observation.
	type Error;

	/// Identifies the exact read pass this capability can currently serve.
	fn epoch(&self) -> SourceEpoch;

	/// Returns the signed-offset-compatible extent observed when opening this pass.
	fn length(&self) -> u64;

	/// Limits the number of bytes per exact positioned read.
	fn max_window_bytes(&self) -> NonZeroUsize;

	/// Fills the entire requested range from this handle at the given offset.
	/// A failed call may have changed scratch bytes.
	fn read_exact_at(
		&mut self,
		offset: u64,
		bytes: &mut [u8],
	) -> impl Future<Output = Result<(), Self::Error>>;

	/// Rechecks required live observations of the held source before capture.
	/// The result describes this handle's observations within the adapter's
	/// limits, including the inability to detect every concurrent edit.
	///
	/// # Errors
	/// Refuses unavailable or changed required observations.
	fn recheck(&mut self) -> impl Future<Output = Result<(), Self::Error>>;

	/// Verifies exact EOF and final observations, and closes the held read handle.
	/// The adapter retains its epoch for comparison after successful closure.
	///
	/// # Errors
	/// Fails if the full source, final observations, EOF, or handle closure
	/// cannot be confirmed. A failed close provides no capture evidence.
	fn finish(&mut self) -> impl Future<Output = Result<(), Self::Error>>;
}

/// Exclusive private stage with a barrier for a partially written prefix.
pub trait CheckpointStage: FreshStage {
	/// Adapter-owned local stage identity for the matching checkpoint sink.
	type Binding: Copy;

	/// Synchronizes the held stage at exactly the written prefix end.
	///
	/// # Errors
	/// Fails if identity, extent, or the data barrier cannot be confirmed.
	/// A successful return supplies the exact stage binding for the record.
	fn sync_prefix(&mut self, end: u64) -> Result<Self::Binding, Self::Error>;
}

/// A measured nonempty range from a single live pass offered after a data barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CaptureCheckpoint {
	/// Live pass that supplied this range.
	pub epoch: SourceEpoch,
	/// Inclusive logical start in bytes.
	pub offset: u64,
	/// Byte length covered by the range.
	pub length: u64,
	/// Ordinary BLAKE3 digest of source bytes supplied for the range.
	pub digest: [u8; 32],
}

/// Records bounded progress under the caller's already admitted private job.
pub trait CaptureCheckpoints<Binding> {
	/// Failure from recording the checkpoint and its applicable barriers.
	type Error;

	/// Commits evidence for the supplied local stage and source range.
	///
	/// # Errors
	/// Fails if the exact binding or record barrier cannot be established.
	/// Checkpoints remain candidate evidence for restart-time reconciliation.
	fn record(&mut self, stage: Binding, range: CaptureCheckpoint) -> Result<(), Self::Error>;
}

/// Matching observations of one live pass and its private stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CapturedStream {
	/// The read pass used for all requested bytes and live observations.
	pub epoch: SourceEpoch,
	/// Complete captured and independently read-back byte extent.
	pub length: u64,
	/// Ordinary BLAKE3 digest of the bytes supplied by the source handle.
	pub source_digest: [u8; 32],
	/// Independent measurement of the private staged stream.
	pub stage_digest: ContentDigest,
}

/// A held private stage and its matching live stream evidence.
#[derive(Debug)]
pub struct ObservedCapture<S> {
	stage: S,
	stream: CapturedStream,
}

impl<S> ObservedCapture<S> {
	/// Returns the unchanged private stage capability and live evidence.
	#[must_use]
	pub fn into_parts(self) -> (S, CapturedStream) {
		(self.stage, self.stream)
	}
}

/// The private stage and live evidence, or the first failed boundary.
pub type CaptureResult<S, R, W, C> = Result<ObservedCapture<S>, CaptureError<R, W, C>>;

/// Captures one held live source from byte zero into an already owned fresh stage.
///
/// The coordinator issues one exact source read at a time, writes each complete
/// window, and records bounded range evidence only after the stage prefix barrier.
/// It closes the writer, independently reads the entire stage, then finishes the
/// source by checking live observations, exact EOF and handle closure. The caller
/// owns the fresh stage and job, the expected epoch, cancellation and execution
/// context for synchronous
/// destination calls. Native metadata and publication require separate work.
///
/// # Errors
/// Refuses invalid extents or scratch, epoch changes, read/write failures,
/// unconfirmed barriers or checkpoints, disagreeing final read-back, or
/// unconfirmed source EOF or closure.
/// On failure or cancellation the private stage and recorded evidence are retained
/// by their destination capabilities and require reconciliation. The caller
/// retires an unfinished source after any failure or cancellation.
pub async fn capture_live<R, W, C>(
	source: &mut R,
	epoch: SourceEpoch,
	writer: W,
	checkpoints: &mut C,
	scratch: &mut [u8],
) -> CaptureResult<W::Closed, R::Error, W::Error, C::Error>
where
	R: CapturedReadAt,
	W: CheckpointStage,
	C: CaptureCheckpoints<W::Binding>,
{
	capture(
		source,
		epoch,
		writer,
		checkpoints,
		scratch,
		CHECKPOINT_BYTES,
	)
	.await
}

async fn capture<R, W, C>(
	source: &mut R,
	epoch: SourceEpoch,
	mut writer: W,
	checkpoints: &mut C,
	scratch: &mut [u8],
	checkpoint_bytes: NonZeroU64,
) -> CaptureResult<W::Closed, R::Error, W::Error, C::Error>
where
	R: CapturedReadAt,
	W: CheckpointStage,
	C: CaptureCheckpoints<W::Binding>,
{
	check_epoch(source.epoch(), epoch)?;
	let length = source.length();
	validate_stream_input(length, scratch.len()).map_err(CaptureError::Input)?;
	let readback_limit = scratch.len().min(W::MAX_CHUNK_BYTES);
	let write_limit = readback_limit.min(source.max_window_bytes().get());
	validate_stream_input(length, write_limit).map_err(CaptureError::Input)?;
	let window_limit = u64::try_from(write_limit).map_err(|_| {
		CaptureError::Input(StreamInputError::ScratchTooLarge {
			length: write_limit,
		})
	})?;
	let stage_length = writer
		.unwritten_length()
		.map_err(|cause| CaptureError::Stage {
			step: StageStep::Admit,
			cause,
		})?;
	if length != stage_length {
		return Err(CaptureError::Extent {
			expected: length,
			found: stage_length,
		});
	}
	source
		.recheck()
		.await
		.map_err(CaptureError::SourceObservation)?;
	check_epoch(source.epoch(), epoch)?;

	let mut source_stream = blake3::Hasher::new();
	let mut checkpoint_stream = blake3::Hasher::new();
	let mut checkpoint_start = 0;
	let mut checkpoint_count = 0;
	let mut offset = 0;
	while offset < length {
		check_epoch(source.epoch(), epoch)?;
		let mut bytes = window_limit.min(length - offset);
		if checkpoint_count < MAX_CHECKPOINTS {
			bytes = bytes.min(checkpoint_bytes.get() - (offset - checkpoint_start));
		}
		let next = offset.checked_add(bytes).ok_or(CaptureError::Input(
			StreamInputError::FileTooLong { length },
		))?;
		let byte_count = usize::try_from(bytes)
			.map_err(|_| CaptureError::Input(StreamInputError::FileTooLong { length }))?;
		let window = &mut scratch[..byte_count];
		source
			.read_exact_at(offset, window)
			.await
			.map_err(|cause| CaptureError::Read { offset, cause })?;
		check_epoch(source.epoch(), epoch)?;
		writer
			.write_next(window)
			.map_err(|cause| CaptureError::Stage {
				step: StageStep::Write { offset },
				cause,
			})?;
		source_stream.update(window);
		if checkpoint_count < MAX_CHECKPOINTS {
			checkpoint_stream.update(window);
			let range_length = next - checkpoint_start;
			if range_length == checkpoint_bytes.get() || next == length {
				let stage = writer
					.sync_prefix(next)
					.map_err(|cause| CaptureError::Stage {
						step: StageStep::SyncPrefix { end: next },
						cause,
					})?;
				let range = CaptureCheckpoint {
					epoch,
					offset: checkpoint_start,
					length: range_length,
					digest: *checkpoint_stream.finalize().as_bytes(),
				};
				checkpoints
					.record(stage, range)
					.map_err(|cause| CaptureError::Checkpoint {
						offset: checkpoint_start,
						cause,
					})?;
				checkpoint_start = next;
				checkpoint_stream.reset();
				checkpoint_count += 1;
			}
		}
		offset = next;
	}

	let source_digest = *source_stream.finalize().as_bytes();
	let stage = writer
		.sync_and_close()
		.map_err(|cause| CaptureError::Stage {
			step: StageStep::Close,
			cause,
		})?;
	let stage_digest = read_back(&stage, length, &mut scratch[..readback_limit])?;
	if &source_digest != stage_digest.as_bytes() {
		return Err(CaptureError::DigestMismatch);
	}
	source.finish().await.map_err(CaptureError::SourceFinish)?;
	check_epoch(source.epoch(), epoch)?;

	Ok(ObservedCapture {
		stage,
		stream: CapturedStream {
			epoch,
			length,
			source_digest,
			stage_digest,
		},
	})
}

fn check_epoch<R, W, C>(
	found: SourceEpoch,
	expected: SourceEpoch,
) -> Result<(), CaptureError<R, W, C>> {
	if found != expected {
		return Err(CaptureError::Epoch { expected, found });
	}
	Ok(())
}

fn read_back<S: ClosedStage, R, C>(
	stage: &S,
	length: u64,
	scratch: &mut [u8],
) -> Result<ContentDigest, CaptureError<R, S::Error, C>> {
	let reader = stage
		.open_read_back()
		.map_err(|cause| CaptureError::Stage {
			step: StageStep::OpenReadBack,
			cause,
		})?;
	let observed = reader.length();
	if observed != length {
		return Err(CaptureError::Extent {
			expected: length,
			found: observed,
		});
	}
	let digest = measure_at(length, scratch, |offset, bytes| {
		reader.read_exact_at(offset, bytes)
	})
	.map_err(CaptureError::ReadBack)?;
	reader
		.recheck_observation()
		.map_err(|cause| CaptureError::Stage {
			step: StageStep::RecheckReadBack,
			cause,
		})?;
	Ok(digest)
}
