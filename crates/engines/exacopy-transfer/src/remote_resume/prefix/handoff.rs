use exacopy_journal::remote_download::checkpoints::RemotePrefixHistory;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::{RemoteDownloadContext, RemoteScopeDigest};

use crate::remote_capture::{CapturedReadAt, SourceEpoch};

use super::{
	PrefixVerificationError as Error, RetainedPrefixView, VerifiedRetainedPrefix, verify_history,
};

mod lending;

pub use lending::{LentRetainedReader, LentRetainedSuffix, SuffixSourceObservation};
use lending::{check_source, read_next_suffix};

type HandoffError<R, L> =
	Error<<R as CapturedReadAt>::Error, <L as exacopy_endpoint::ReadView>::Error>;

/// Compared prefix with the exact retained view and live source still held.
///
/// A native adapter must make `L` own its actual held reader and lease
/// association. The engine preserves that value and confers no write authority.
#[must_use]
pub struct VerifiedHeldRetainedPrefix<'source, R, L> {
	prefix: VerifiedRetainedPrefix<'source, R>,
	retained: L,
	name: Box<[u8]>,
}

impl<'source, R, L> VerifiedHeldRetainedPrefix<'source, R, L> {
	/// Read-only facts from the complete prefix comparison.
	#[must_use]
	pub const fn prefix(&self) -> &VerifiedRetainedPrefix<'source, R> {
		&self.prefix
	}

	/// Carries the live source, digest state and exact retained reader into suffix reads.
	pub fn into_continuation(self) -> RetainedContinuation<'source, R, L> {
		let next = self.prefix.extent;
		RetainedContinuation {
			held: self,
			next: Some(next),
		}
	}
}

/// Compares the complete opaque historical cover and bounded uncheckpointed
/// tail, consuming custody of the same retained reader used for comparison.
///
/// # Errors
/// Refuses mismatched history, stale observations, invalid bounds or unequal
/// bytes. On failure the adapter's reader is dropped and the stage remains private.
pub async fn verify_held_retained_prefix<'source, R, L>(
	inventory: &RemotePrefixHistory<'_>,
	source: &'source mut R,
	epoch: SourceEpoch,
	retained: L,
	scratch: &mut [u8],
) -> Result<VerifiedHeldRetainedPrefix<'source, R, L>, HandoffError<R, L>>
where
	R: CapturedReadAt,
	L: RetainedPrefixView,
{
	let prefix = verify_history(inventory, source, epoch, &retained, scratch).await?;
	Ok(VerifiedHeldRetainedPrefix {
		prefix,
		retained,
		name: inventory.name().into(),
	})
}

/// Sequential read-only continuation of the same source pass.
///
/// The running digest includes every verified prefix byte and each fresh suffix
/// read. A failed or dropped in-progress read prevents further use of this state.
#[must_use]
pub struct RetainedContinuation<'source, R, L> {
	held: VerifiedHeldRetainedPrefix<'source, R, L>,
	next: Option<u64>,
}

impl<'source, R: CapturedReadAt, L: RetainedPrefixView> RetainedContinuation<'source, R, L> {
	/// Reads the next complete source window, bounded by the supplied scratch and source.
	///
	/// Returns `None` at the observed length. Use [Self::finish] to check actual EOF.
	///
	/// # Errors
	/// Refuses stale source observations, invalid scratch, or a failed or cancelled read.
	pub async fn read_next<'buffer>(
		&mut self,
		scratch: &'buffer mut [u8],
	) -> Result<Option<&'buffer [u8]>, HandoffError<R, L>> {
		read_next_suffix(&mut self.held.prefix, &mut self.next, scratch).await
	}

	/// Checks actual source EOF and handle closure while retaining the original reader.
	///
	/// A prefix already as long as the source needs no suffix reads. This reports
	/// source closure only. It releases the terminal source borrow so the adapter
	/// can retire the transport while the result continues to hold the retained reader.
	/// The adapter still owns native stage barriers.
	///
	/// # Errors
	/// Refuses incomplete coverage, a changed stage or source, or failed source finish.
	pub async fn finish(mut self) -> Result<ObservedRetainedContinuation<L>, HandoffError<R, L>> {
		let offset = self.next.take().ok_or(Error::ContinuationStopped)?;
		let length = self.held.prefix.source_length;
		if offset != length {
			return Err(Error::IncompleteContinuation { offset, length });
		}
		check_source(&self.held.prefix)?;
		self.recheck_retained()?;
		self.held
			.prefix
			.source
			.finish()
			.await
			.map_err(Error::SourceFinish)?;
		check_source(&self.held.prefix)?;
		self.recheck_retained()?;
		let prefix = self.held.prefix;
		Ok(ObservedRetainedContinuation {
			_retained: self.held.retained,
			boundary: prefix.boundary,
			scope: prefix.scope,
			context: prefix.context,
			epoch: prefix.epoch,
			length,
			digest: prefix.digest(),
		})
	}

	fn recheck_retained(&self) -> Result<(), HandoffError<R, L>> {
		let retained = &self.held.retained;
		let prefix = &self.held.prefix;
		retained
			.recheck_observation()
			.map_err(Error::StageObservation)?;
		let actual = retained.identity();
		if actual.name.as_bytes() != self.held.name.as_ref()
			|| actual.directory != prefix.stage.directory
			|| actual.file != prefix.stage.file
		{
			return Err(Error::StageIdentity);
		}
		let actual = retained.length();
		if actual != prefix.extent {
			return Err(Error::StageExtentChanged {
				expected: prefix.extent,
				actual,
			});
		}
		Ok(())
	}
}

/// Complete live source evidence, with custody of the exact original retained reader.
///
/// The retained file has only the compared prefix. This is not independent
/// read-back of a finished stage and supplies no native effect authority.
#[must_use]
pub struct ObservedRetainedContinuation<L> {
	_retained: L,
	boundary: RemoteReplayBoundary,
	scope: RemoteScopeDigest,
	context: RemoteDownloadContext,
	epoch: SourceEpoch,
	length: u64,
	digest: [u8; 32],
}

impl<L> ObservedRetainedContinuation<L> {
	/// The exact fresh source epoch used for prefix and suffix.
	#[must_use]
	pub const fn epoch(&self) -> SourceEpoch {
		self.epoch
	}

	/// Original accepted historical boundary used for prefix comparison.
	#[must_use]
	pub const fn boundary(&self) -> RemoteReplayBoundary {
		self.boundary
	}

	/// Complete observed source length after exact EOF confirmation.
	#[must_use]
	pub const fn length(&self) -> u64 {
		self.length
	}

	/// Ordinary BLAKE3-256 of the whole fresh source pass.
	#[must_use]
	pub const fn digest(&self) -> [u8; 32] {
		self.digest
	}

	/// Signed remote scope of the selected past and the current live pass.
	#[must_use]
	pub const fn scope(&self) -> RemoteScopeDigest {
		self.scope
	}

	/// Authenticated owner, job and entry matched to the retained history.
	#[must_use]
	pub const fn context(&self) -> RemoteDownloadContext {
		self.context
	}
}
