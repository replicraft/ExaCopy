//! Sequential Linux staging and independent read-back verification.

use exacopy_content::{ContentDigest, copy_and_measure_at, measure_at, validate_stream_input};
use exacopy_endpoint::UnixComponent;
use exacopy_model::{CopyBinding, CopyEffect, CopyEvent, CopyPhase, CopySession};
use exacopy_platform::linux::{
	ClosedStage, ExtendedAttributes, FileIdentity, SourceFile, StageDirectory,
};

mod error;
mod job;
mod local_copy;
mod plan;
mod receipt;

pub use error::{StageCopyError, StageFailure};
pub use job::{JobBootstrap, JobBootstrapError, JobStep, PreparedJob};
pub use local_copy::{CopyProfile, CopyRoots, LocalCopyError, copy_new_file, plan_new_file};
pub use plan::{
	DestinationPlanBinding, LocalCopyPlan, LocalCopyPlanError, MAX_LOCAL_COPY_PLAN_BYTES,
	PlanAttempt, SourcePlanBinding,
};
pub use receipt::{CopyReceipt, MAX_COPY_RECEIPT_BYTES, ReceiptError, ReceiptEvidence};

const SPECIAL_MODE_BITS: u32 = 0o7000;

/// The planned names and attempt identity for a single new file.
#[derive(Debug, Clone, Copy)]
pub struct StageRequest<'name> {
	/// The exclusive file name inside the owned stage directory.
	pub stage_name: UnixComponent<'name>,
	/// The intended name in the held destination root.
	pub target: UnixComponent<'name>,
	/// The job, entry, epoch, and stage binding allocated by the coordinator.
	pub binding: CopyBinding,
}

/// A private stage with independent source-stream and destination read-back agreement.
///
/// This type retains the pinned read-only handle and model session. Publication needs
/// separately recorded intent and recovery evidence.
#[derive(Debug)]
pub struct VerifiedStage<'stage> {
	stage: ClosedStage<'stage>,
	session: CopySession,
	digest: ContentDigest,
}

impl VerifiedStage<'_> {
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

	/// Compares the physical stage identity while this pinned handle remains held.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.stage.identity()
	}

	/// The model phase backed by observations made during this attempt.
	#[must_use]
	pub const fn phase(&self) -> CopyPhase {
		self.session.phase()
	}
}

/// Copies one observed Linux source stream into a new, private, independently verified stage.
///
/// The caller retains root authority and a unique attempt binding. The same bounded buffer
/// is used first for sequential copying and later for read-back, after writer release.
/// This path accepts the baseline native metadata subset. The source is live observed, and
/// independent read-back can be served by the OS cache.
///
/// # Errors
/// The current model phase and cause identify failure. An allocated stage remains private
/// for inspection. No target creation or deletion occurs during this operation.
pub fn stage_verified<'stage>(
	source: &SourceFile,
	directory: &'stage StageDirectory<'_>,
	request: StageRequest<'_>,
	scratch: &mut [u8],
) -> Result<VerifiedStage<'stage>, StageCopyError> {
	stage_with_preparation(source, directory, request, scratch, |_| Ok(()))
}

fn stage_with_preparation<'stage>(
	source: &SourceFile,
	directory: &'stage StageDirectory<'_>,
	request: StageRequest<'_>,
	scratch: &mut [u8],
	record: impl FnOnce(FileIdentity) -> Result<(), StageFailure>,
) -> Result<VerifiedStage<'stage>, StageCopyError> {
	let mut session = CopySession::new(request.binding);
	let result = prepare(source, directory, request, scratch, &mut session, record);
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

fn prepare<'stage>(
	source: &SourceFile,
	directory: &'stage StageDirectory<'_>,
	request: StageRequest<'_>,
	scratch: &mut [u8],
	session: &mut CopySession,
	record: impl FnOnce(FileIdentity) -> Result<(), StageFailure>,
) -> Result<(ClosedStage<'stage>, ContentDigest), StageFailure> {
	validate_stream_input(source.len(), scratch.len()).map_err(StageFailure::Input)?;
	check_source(source)?;
	let mut writable = directory
		.create_file(request.stage_name, request.target, request.binding)
		.map_err(StageFailure::Stage)?;
	if writable.identity() == source.identity() {
		return Err(StageFailure::Alias);
	}
	writable
		.check_ownership(source.observation())
		.map_err(StageFailure::Stage)?;
	record(writable.identity())?;
	if !matches!(
		session.apply(request.binding, CopyEvent::StagePrepared)?,
		Some(CopyEffect::ReadSource(read)) if read.binding() == request.binding
	) {
		return Err(StageFailure::UnexpectedEffect);
	}

	let source_digest = copy_and_measure_at(
		source.len(),
		scratch,
		|offset, bytes| source.read_exact_at(offset, bytes),
		|offset, bytes| writable.write_all_at(offset, bytes),
	)
	.map_err(StageFailure::Copy)?;
	writable
		.set_len(source.len())
		.map_err(StageFailure::Stage)?;
	observe(session, request.binding, CopyEvent::WritersJoined)?;
	writable.flush().map_err(StageFailure::Stage)?;
	observe(session, request.binding, CopyEvent::DataFlushed)?;

	let stage = writable.close_writes().map_err(StageFailure::Stage)?;
	if stage.length() != source.len() {
		return Err(StageFailure::LengthMismatch {
			expected: source.len(),
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
	observe(session, request.binding, CopyEvent::ReadbackVerified)?;

	check_source(source)?;
	let stage = stage
		.apply_metadata(source.observation())
		.map_err(StageFailure::Stage)?;
	directory.sync_directory().map_err(StageFailure::Stage)?;
	check_source(source)?;
	observe(session, request.binding, CopyEvent::MetadataReady)?;
	observe(session, request.binding, CopyEvent::StageSealed)?;
	Ok((stage, source_digest))
}

fn check_source(source: &SourceFile) -> Result<(), StageFailure> {
	let attributes = source.extended_attributes().map_err(StageFailure::Source)?;
	source.recheck_observation().map_err(StageFailure::Source)?;
	source.check_logical_eof().map_err(StageFailure::Source)?;
	if attributes != ExtendedAttributes::NoneVisible {
		return Err(StageFailure::SourceAttributes(attributes));
	}
	let mode = source.observation().mode();
	if mode & SPECIAL_MODE_BITS != 0 {
		return Err(StageFailure::UnsupportedSourceMode { mode });
	}
	Ok(())
}

fn observe(
	session: &mut CopySession,
	binding: CopyBinding,
	event: CopyEvent,
) -> Result<(), StageFailure> {
	if session.apply(binding, event)?.is_some() {
		return Err(StageFailure::UnexpectedEffect);
	}
	Ok(())
}
