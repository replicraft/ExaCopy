//! Bounded historical checkpoints for independent current-prefix verification.

use crate::frame::ChainHead;
use crate::{StreamDigest, StreamLength};

use super::finalization_replay::RemoteFinalizationPhase;
use super::replay::{
	RemoteDownloadReplay, RemotePreparedStage, RemoteReplayAttempt, RemoteReplayBoundary,
};
use super::{
	RemoteDownloadContext, RemoteDownloadError as Error, RemoteDownloadOwnerRecord, RemoteEpochs,
	RemoteScopeDigest, RemoteSourceObservation,
};

mod prefix;

pub(super) use prefix::PrefixOwner;
pub use prefix::{RemoteHistoricalRange, RemotePrefixHistory};

/// One canonical checkpoint whose context, epochs and contiguous position passed replay.
///
/// Verification here means journal admission. The bytes still need fresh source and
/// held-stage measurements before reuse. There is no public row constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteVerifiedCheckpoint {
	head: ChainHead,
	ordinal: u16,
	offset: u64,
	length: u64,
	digest: StreamDigest,
}

impl RemoteVerifiedCheckpoint {
	pub(super) const fn new(
		head: ChainHead,
		ordinal: u16,
		offset: u64,
		length: u64,
		digest: StreamDigest,
	) -> Self {
		Self {
			head,
			ordinal,
			offset,
			length,
			digest,
		}
	}

	/// Exact checkpoint frame in the admitted chain.
	#[must_use]
	pub const fn head(self) -> ChainHead {
		self.head
	}

	/// One-based checkpoint ordinal in this attempt.
	#[must_use]
	pub const fn ordinal(self) -> u16 {
		self.ordinal
	}

	/// Inclusive logical start offset.
	#[must_use]
	pub const fn offset(self) -> u64 {
		self.offset
	}

	/// Positive bounded logical byte count.
	#[must_use]
	pub const fn length(self) -> u64 {
		self.length
	}

	/// Historical ordinary BLAKE3 digest, to be independently checked against current bytes.
	#[must_use]
	pub const fn digest(self) -> StreamDigest {
		self.digest
	}
}

/// Read-only evidence for the latest clean, unsealed, physically bound capture declaration.
///
/// The input owner and bootstrap were authenticated by the selected replay. This
/// object supplies no current namespace observation, source identity or writer grant.
pub struct RemoteActiveCheckpoints<'scan> {
	owner: &'scan RemoteDownloadOwnerRecord,
	replay: &'scan RemoteDownloadReplay,
	attempt: &'scan RemoteReplayAttempt,
	prepared: RemotePreparedStage,
	rows: &'scan [RemoteVerifiedCheckpoint],
	qualification: [u8; 32],
}

impl<'scan> RemoteActiveCheckpoints<'scan> {
	pub(super) fn from_replay(
		owner: &'scan RemoteDownloadOwnerRecord,
		replay: &'scan RemoteDownloadReplay,
		phase: RemoteFinalizationPhase,
		qualification: [u8; 32],
	) -> Result<Self, Error> {
		if replay.issue().is_some() || phase != RemoteFinalizationPhase::Capture {
			return Err(Error::Binding);
		}
		let rows = replay.active_checkpoints.as_deref().ok_or(Error::Binding)?;
		let attempt = replay.attempts().last().ok_or(Error::Binding)?;
		let prepared = attempt.prepared().ok_or(Error::Binding)?;
		if rows.is_empty() || rows.len() != usize::from(attempt.checkpoint_count()) {
			return Err(Error::Binding);
		}
		Ok(Self {
			owner,
			replay,
			attempt,
			prepared,
			rows,
			qualification,
		})
	}

	/// Returns the whole original coverage for current retained-byte verification.
	///
	/// # Errors
	/// Retains a canonical scope encoding failure.
	pub fn prefix_history(&self) -> Result<RemotePrefixHistory<'scan>, Error> {
		RemotePrefixHistory::original(
			PrefixOwner::from_owner(self.owner)?,
			self.attempt,
			self.prepared,
			self.boundary(),
			self.qualification,
			self.rows,
		)
	}

	/// Exact authenticated owner/job/entry context.
	#[must_use]
	pub fn context(&self) -> RemoteDownloadContext {
		RemoteDownloadContext::for_owner(self.owner)
	}

	/// Exact immutable scope digest selected by this owner.
	/// # Errors
	/// Retains any canonical scope encoding failure.
	pub fn scope(&self) -> Result<RemoteScopeDigest, Error> {
		self.owner.manifest().scope.digest()
	}

	/// Maximum source extent authorized by the selected signed scope.
	#[must_use]
	pub fn maximum_extent(&self) -> StreamLength {
		self.owner.manifest().scope.maximum_extent
	}

	/// Clear EOF boundary of the entire scanned history, not just the last checkpoint.
	#[must_use]
	pub const fn boundary(&self) -> RemoteReplayBoundary {
		self.replay.boundary()
	}

	/// Native identities declared by the admitted physical preparation frame.
	#[must_use]
	pub const fn prepared(&self) -> RemotePreparedStage {
		self.prepared
	}

	/// Exact fresh-allocation frame of this attempt.
	#[must_use]
	pub const fn allocation(&self) -> ChainHead {
		self.attempt.allocation()
	}

	/// Historical run and held-source labels. A new pass must acquire fresh labels.
	#[must_use]
	pub const fn epochs(&self) -> RemoteEpochs {
		self.attempt.epochs()
	}

	/// Exact raw allocated stage basename.
	#[must_use]
	pub fn name(&self) -> &[u8] {
		self.attempt.name()
	}

	/// Stage nonce from that exact allocation.
	#[must_use]
	pub const fn nonce(&self) -> &[u8; 16] {
		self.attempt.nonce()
	}

	/// Original server-reported live attributes; these do not establish source identity.
	#[must_use]
	pub const fn source(&self) -> RemoteSourceObservation {
		self.attempt.source()
	}

	/// Exclusive end of the historical contiguous checkpoint prefix.
	#[must_use]
	pub const fn covered_extent(&self) -> u64 {
		self.attempt.covered_extent()
	}

	/// Selected qualification digest, not proof of any current native facts.
	#[must_use]
	pub const fn expected_qualification(&self) -> [u8; 32] {
		self.qualification
	}

	/// At most 4,096 journal-admitted rows for this one active attempt.
	#[must_use]
	pub const fn checkpoints(&self) -> &[RemoteVerifiedCheckpoint] {
		self.rows
	}
}
