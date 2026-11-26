//! Immutable historical coverage used by the current retained-byte verifier.

use crate::{StreamDigest, StreamLength};

use super::RemoteVerifiedCheckpoint;
use crate::remote_download::continuation::replay::RemoteContinuedCapture;
use crate::remote_download::continuation::{CoverageBasis, PriorPreparation};
use crate::remote_download::replay::{
	RemotePreparedStage, RemoteReplayAttempt, RemoteReplayBoundary,
};
use crate::remote_download::{
	RemoteDownloadContext, RemoteDownloadError as Error, RemoteDownloadOwnerRecord, RemoteEpochs,
	RemoteScopeDigest, RemoteSourceObservation,
};

#[derive(Clone, Copy)]
pub(in crate::remote_download) struct PrefixOwner {
	context: RemoteDownloadContext,
	scope: RemoteScopeDigest,
	maximum_extent: StreamLength,
}

impl PrefixOwner {
	pub(in crate::remote_download) fn from_owner(
		owner: &RemoteDownloadOwnerRecord,
	) -> Result<Self, Error> {
		Ok(Self {
			context: RemoteDownloadContext::for_owner(owner),
			scope: owner.manifest().scope.digest()?,
			maximum_extent: owner.manifest().scope.maximum_extent,
		})
	}
}

/// One historical digest to compare against current held bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteHistoricalRange {
	/// Inclusive logical start offset.
	pub offset: u64,
	/// Logical byte count.
	pub length: u64,
	/// Ordinary BLAKE3 digest recorded in the selected history.
	pub digest: StreamDigest,
}

/// The entire historical coverage of a clean prepared capture.
///
/// This borrowed value comes from successful journal replay. A continued history
/// always includes the signed aggregate starting at zero before any suffix rows.
/// The evidence carries no current reader, writer, barrier or publication authority.
pub struct RemotePrefixHistory<'scan> {
	owner: PrefixOwner,
	attempt: &'scan RemoteReplayAttempt,
	prepared: RemotePreparedStage,
	boundary: RemoteReplayBoundary,
	qualification: [u8; 32],
	rows: &'scan [RemoteVerifiedCheckpoint],
	basis: CoverageBasis,
	continued: Option<ContinuedPrefix<'scan>>,
}

struct ContinuedPrefix<'scan> {
	capture: &'scan RemoteContinuedCapture,
	grant: [u8; 32],
}

impl<'scan> RemotePrefixHistory<'scan> {
	pub(super) fn original(
		owner: PrefixOwner,
		attempt: &'scan RemoteReplayAttempt,
		prepared: RemotePreparedStage,
		boundary: RemoteReplayBoundary,
		qualification: [u8; 32],
		rows: &'scan [RemoteVerifiedCheckpoint],
	) -> Result<Self, Error> {
		let latest = rows.last().ok_or(Error::Binding)?;
		Ok(Self {
			owner,
			attempt,
			prepared,
			boundary,
			qualification,
			rows,
			basis: CoverageBasis::Checkpoint {
				head: latest.head(),
				ordinal: latest.ordinal(),
			},
			continued: None,
		})
	}

	pub(in crate::remote_download) fn continued(
		owner: PrefixOwner,
		attempt: &'scan RemoteReplayAttempt,
		boundary: RemoteReplayBoundary,
		qualification: [u8; 32],
		grant: [u8; 32],
		capture: &'scan RemoteContinuedCapture,
	) -> Result<Self, Error> {
		let rows = capture.checkpoints();
		let basis = match rows.last() {
			Some(latest) => CoverageBasis::Checkpoint {
				head: latest.head(),
				ordinal: latest.ordinal(),
			},
			None => CoverageBasis::ContinuedPrefix(capture.admitted_at().head),
		};
		Ok(Self {
			owner,
			attempt,
			prepared: attempt.prepared().ok_or(Error::Binding)?,
			boundary,
			qualification,
			rows,
			basis,
			continued: Some(ContinuedPrefix { capture, grant }),
		})
	}

	/// Exact authenticated owner, job and entry.
	#[must_use]
	pub const fn context(&self) -> RemoteDownloadContext {
		self.owner.context
	}

	/// Exact immutable scope digest.
	#[must_use]
	pub const fn scope(&self) -> RemoteScopeDigest {
		self.owner.scope
	}

	/// Maximum extent authorized by the signed scope.
	#[must_use]
	pub const fn maximum_extent(&self) -> StreamLength {
		self.owner.maximum_extent
	}

	/// Exact clear EOF boundary of the historical scan.
	#[must_use]
	pub const fn boundary(&self) -> RemoteReplayBoundary {
		self.boundary
	}

	/// Original native preparation and stage identities.
	#[must_use]
	pub const fn prepared(&self) -> RemotePreparedStage {
		self.prepared
	}

	/// Raw basename selected by the exact original allocation.
	#[must_use]
	pub fn name(&self) -> &[u8] {
		self.attempt.name()
	}

	/// Historical active preparation, separate from original native identities.
	#[must_use]
	pub const fn active(&self) -> PriorPreparation {
		match &self.continued {
			Some(active) => PriorPreparation::Continued(active.capture.admitted_at().head),
			None => PriorPreparation::Original(self.prepared.head),
		}
	}

	/// Historical run and source of the active writer.
	#[must_use]
	pub const fn epochs(&self) -> RemoteEpochs {
		match &self.continued {
			Some(active) => active.capture.epochs(),
			None => self.attempt.epochs(),
		}
	}

	/// Historical source observation from the active writer.
	#[must_use]
	pub const fn source(&self) -> RemoteSourceObservation {
		match &self.continued {
			Some(active) => active.capture.source(),
			None => self.attempt.source(),
		}
	}

	/// Historical qualification selected at replay.
	#[must_use]
	pub const fn expected_qualification(&self) -> [u8; 32] {
		self.qualification
	}

	/// Exact archived continued grant digest, when supplied by this profile.
	#[must_use]
	pub const fn recorded_grant(&self) -> Option<[u8; 32]> {
		match &self.continued {
			Some(active) => Some(active.grant),
			None => None,
		}
	}

	/// Latest durable coverage anchor of this capture.
	#[must_use]
	pub const fn coverage_basis(&self) -> CoverageBasis {
		self.basis
	}

	/// Exclusive end of the aggregate and all contiguous historical rows.
	#[must_use]
	pub const fn covered_extent(&self) -> u64 {
		match &self.continued {
			Some(active) => active.capture.covered_end(),
			None => self.attempt.covered_extent(),
		}
	}

	/// Every historical digest in ascending byte order starting at offset zero.
	pub fn ranges(&self) -> impl Iterator<Item = RemoteHistoricalRange> + '_ {
		let aggregate = self.continued.as_ref().map(|active| {
			let (extent, digest) = active.capture.adopted_prefix();
			RemoteHistoricalRange {
				offset: 0,
				length: extent.get(),
				digest,
			}
		});
		aggregate
			.into_iter()
			.chain(self.rows.iter().map(|row| RemoteHistoricalRange {
				offset: row.offset(),
				length: row.length(),
				digest: row.digest(),
			}))
	}
}
