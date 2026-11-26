//! Read-only comparison of a retained ordinary SFTP capture prefix with a new held pass.

use exacopy_content::{StreamInputError, validate_stream_input};
use exacopy_endpoint::{ReadView, UnixComponent};
use exacopy_journal::LinuxFileIdentity;
use exacopy_journal::remote_download::checkpoints::RemoteActiveCheckpoints;
use exacopy_journal::remote_download::replay::{RemotePreparedStage, RemoteReplayBoundary};
use exacopy_journal::remote_download::{
	MAX_REMOTE_CHECKPOINT_BYTES, RemoteDownloadContext, RemoteDownloadError, RemoteEpochs,
	RemoteScopeDigest,
};

use crate::remote_capture::{CapturedReadAt, SourceEpoch};

mod compare;
mod error;

pub use error::PrefixVerificationError;

use compare::{Comparison, Mismatch};

/// Native identities and basename observed from the exact retained reader.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RetainedPrefixIdentity<'name> {
	/// Actual validated private basename under the held job.
	pub name: UnixComponent<'name>,
	/// Physical stage directory identity.
	pub directory: LinuxFileIdentity,
	/// Physical stage file identity.
	pub file: LinuxFileIdentity,
}

/// Read-only retained file held by the application under the exclusive job lease.
///
/// The observation must describe the exact named object used by this reader.
/// The adapter rechecks that object's identity, extent and private custody in
/// `recheck_observation`. Neither method confers write or publication authority.
pub trait RetainedPrefixView: ReadView {
	/// Returns the identities bound to this held reader.
	fn identity(&self) -> RetainedPrefixIdentity<'_>;
}

/// Verified prefix evidence holds the exact new source until the caller releases it.
///
/// This capability supplies no journal, write or publication authority. The
/// source has been read through `extent()`, with no terminal EOF or close check.
#[must_use]
pub struct VerifiedRetainedPrefix<'source, R> {
	source: &'source mut R,
	epoch: SourceEpoch,
	source_length: u64,
	extent: u64,
	checkpoint_extent: u64,
	hasher: blake3::Hasher,
	scope: RemoteScopeDigest,
	context: RemoteDownloadContext,
	qualification: [u8; 32],
	stage: RemotePreparedStage,
	previous: RemoteEpochs,
	boundary: RemoteReplayBoundary,
}

impl<'source, R> VerifiedRetainedPrefix<'source, R> {
	/// The exact new live epoch supplying the matching prefix.
	#[must_use]
	pub const fn epoch(&self) -> SourceEpoch {
		self.epoch
	}

	/// Observed complete file length of the fresh source pass.
	#[must_use]
	pub const fn source_length(&self) -> u64 {
		self.source_length
	}

	/// Exclusive end of the compared local and fresh remote prefix.
	#[must_use]
	pub const fn extent(&self) -> u64 {
		self.extent
	}

	/// Exclusive end additionally checked against historical checkpoint digests.
	#[must_use]
	pub const fn checkpoint_extent(&self) -> u64 {
		self.checkpoint_extent
	}

	/// Signed remote scope of the selected historical prefix.
	#[must_use]
	pub const fn scope(&self) -> RemoteScopeDigest {
		self.scope
	}

	/// Authenticated owner, job and entry of the selected historical prefix.
	#[must_use]
	pub const fn context(&self) -> RemoteDownloadContext {
		self.context
	}

	/// Historical replay's selected qualification digest.
	#[must_use]
	pub const fn expected_qualification(&self) -> [u8; 32] {
		self.qualification
	}

	/// Exact original preparation and physical stage identities.
	#[must_use]
	pub const fn stage(&self) -> RemotePreparedStage {
		self.stage
	}

	/// Historical recorded run and source labels of the checkpointed bytes.
	#[must_use]
	pub const fn previous_epochs(&self) -> RemoteEpochs {
		self.previous
	}

	/// Last accepted journal boundary supplying the historical checkpoint set.
	#[must_use]
	pub const fn boundary(&self) -> RemoteReplayBoundary {
		self.boundary
	}

	/// Ordinary BLAKE3-256 of the exact freshly read prefix.
	#[must_use]
	pub fn digest(&self) -> [u8; 32] {
		*self.hasher.finalize().as_bytes()
	}

	/// Releases the same held read-only source for subsequent caller operations.
	#[must_use]
	pub fn into_source(self) -> &'source mut R {
		self.source
	}
}

/// Checks every proposed retained byte against the fresh held source.
///
/// The application independently admits the same signed peer, route, grant
/// and rooted path on the new connection, and owns the exact private existing
/// stage and job lease used to obtain the inventory and retained reader. Replay is
/// historical evidence. This operation rereads it against current bytes.
/// Its two comparison windows share the bounded caller scratch space.
///
/// # Errors
/// Refuses stale source epochs, mismatched stage identities and extents,
/// more than one checkpoint interval of uncheckpointed tail, bytes beyond
/// the prior writer's admitted extent, mismatched fresh or historical
/// bytes, and any unconfirmed source or local read.
pub async fn verify_retained_prefix<'source, R, L>(
	inventory: &RemoteActiveCheckpoints<'_>,
	source: &'source mut R,
	epoch: SourceEpoch,
	retained: &L,
	scratch: &mut [u8],
) -> Result<VerifiedRetainedPrefix<'source, R>, PrefixVerificationError<R::Error, L::Error>>
where
	R: CapturedReadAt,
	L: RetainedPrefixView,
{
	use PrefixVerificationError as Error;

	let scope = inventory.scope().map_err(Error::History)?;
	let source_length = source.length();
	validate_stream_input(source_length, scratch.len()).map_err(Error::Input)?;
	if epoch.get() <= inventory.epochs().source.get() || source.epoch() != epoch {
		return Err(Error::Epoch);
	}
	if source_length > inventory.maximum_extent().get() {
		return Err(Error::SourceLimit {
			length: source_length,
			limit: inventory.maximum_extent().get(),
		});
	}
	let extent = retained.length();
	let tail = extent
		.checked_sub(inventory.covered_extent())
		.filter(|tail| *tail <= MAX_REMOTE_CHECKPOINT_BYTES)
		.ok_or(Error::RetainedExtent {
			extent,
			checkpoint: inventory.covered_extent(),
		})?;
	let prior_length = inventory.source().length().get();
	if extent > prior_length {
		return Err(Error::RetainedBeyondPrior {
			extent,
			prior: prior_length,
		});
	}
	if source_length < extent {
		return Err(Error::SourceShorter {
			source: source_length,
			retained: extent,
		});
	}
	let width = (scratch.len() / 2).min(source.max_window_bytes().get());
	validate_stream_input(extent, width).map_err(Error::Input)?;
	let step = u64::try_from(width)
		.map_err(|_| Error::Input(StreamInputError::ScratchTooLarge { length: width }))?;
	let (source_window, rest) = scratch.split_at_mut(width);
	let mut comparison = Comparison::new(
		source,
		retained,
		epoch,
		source_length,
		source_window,
		&mut rest[..width],
		step,
	);
	comparison.recheck_stage(inventory, extent)?;
	comparison.recheck_source().await?;

	let mut mismatch = None;
	for checkpoint in inventory.checkpoints() {
		let offset = checkpoint.offset();
		let end = offset
			.checked_add(checkpoint.length())
			.ok_or(Error::History(RemoteDownloadError::FrameBinding))?;
		mismatch = comparison
			.check(offset..end, Some(*checkpoint.digest().as_bytes()))
			.await?;
		if mismatch.is_some() {
			break;
		}
	}
	if mismatch.is_none() && tail > 0 {
		mismatch = comparison
			.check(inventory.covered_extent()..extent, None)
			.await?;
	}
	comparison.recheck_source().await?;
	comparison.recheck_stage(inventory, extent)?;
	match mismatch {
		Some(Mismatch::Source { offset }) => return Err(Error::SourceMismatch { offset }),
		Some(Mismatch::Checkpoint { offset }) => return Err(Error::CheckpointMismatch { offset }),
		Some(Mismatch::Tail { offset }) => return Err(Error::TailMismatch { offset }),
		None => (),
	}
	let hasher = comparison.into_hasher();
	Ok(VerifiedRetainedPrefix {
		source,
		epoch,
		source_length,
		extent,
		checkpoint_extent: inventory.covered_extent(),
		hasher,
		scope,
		context: inventory.context(),
		qualification: inventory.expected_qualification(),
		stage: inventory.prepared(),
		previous: inventory.epochs(),
		boundary: inventory.boundary(),
	})
}
