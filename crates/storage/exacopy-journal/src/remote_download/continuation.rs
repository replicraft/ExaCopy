//! Signed recorded evidence for a continued capture on one retained inode.
//!
//! The prior kind-40 shape reserves a future replay branch. This codec does
//! not decide which histories are eligible for continuation. Its payload cap
//! is checked before decoding the envelope. A future kind-40 frame reader
//! must apply that cap before allocating or reading the payload.

use ed25519_dalek::{Signature, Signer, SigningKey};
use exacopy_endpoint::UnixComponent;

use crate::frame::{ChainHead, FRAME_OVERHEAD_BYTES, Frame, FrameKind};
use crate::{LinuxFileIdentity, MAX_FIRST_SEGMENT_BYTES, OwnerError, StreamDigest, StreamLength};

use super::replay::RemoteReplayBoundary;
use super::{
	RemoteBootstrapTrust, RemoteDownloadContext, RemoteDownloadError as Error, RemoteEpochs,
	RemoteScopeDigest, RemoteSourceObservation,
};

pub mod checkpoint;
pub mod replay;
mod validation;
mod wire;

/// Maximum canonical continuation envelope size, scoped to kind 40.
pub const MAX_REMOTE_CONTINUATION_PAYLOAD_BYTES: usize = 1024;

/// The prior active preparation, distinct from the original inode binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PriorPreparation {
	/// An original EntryPrepared.
	Original(ChainHead),
	/// A RemoteCaptureContinued for the same inode.
	Continued(ChainHead),
}

impl PriorPreparation {
	const fn head(self) -> ChainHead {
		match self {
			Self::Original(head) | Self::Continued(head) => head,
		}
	}
}

/// The immediately preceding durable coverage basis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageBasis {
	/// The prior run's last consecutive checkpoint.
	Checkpoint {
		/// Exact prior checkpoint head.
		head: ChainHead,
		/// Nonzero ordinal within the prior run.
		ordinal: u16,
	},
	/// The prior continued declaration, with implicit checkpoint ordinal zero.
	ContinuedPrefix(ChainHead),
}

/// Recorded lineage of the retained private inode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteContinuationPrior<'name> {
	/// Signed stage directory bootstrap head.
	pub bootstrap: ChainHead,
	/// Original private basename allocation head.
	pub allocation: ChainHead,
	/// Original EntryPrepared head.
	pub prepared: ChainHead,
	/// Active preparation for the previous run.
	pub active: PriorPreparation,
	/// Previous run and source epoch labels.
	pub epochs: RemoteEpochs,
	/// Original private basename.
	pub name: UnixComponent<'name>,
	/// Original allocation's nonzero nonce.
	pub nonce: [u8; 16],
}

/// Exact earlier coverage that the new run adopts and may extend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteContinuationCoverage {
	/// Last recorded coverage basis.
	pub basis: CoverageBasis,
	/// Earlier covered exclusive end.
	pub end: StreamLength,
}

/// Claims authenticated by the selected job owner.
///
/// The profile encodes fixed declarations of live prefix comparison, an exact
/// retained-prefix barrier and an absent target. These are historical claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteContinuationClaims<'name> {
	/// Signed owner, job and entry.
	pub context: RemoteDownloadContext,
	/// Signed exact source and destination scope.
	pub scope: RemoteScopeDigest,
	/// Complete preceding clean boundary.
	pub previous: RemoteReplayBoundary,
	/// Original inode and prior run lineage.
	pub prior: RemoteContinuationPrior<'name>,
	/// Native stage directory identity as recorded.
	pub directory: LinuxFileIdentity,
	/// Native retained stage identity as recorded.
	pub stage: LinuxFileIdentity,
	/// Earlier coverage independently resolved against the prefix.
	pub coverage: RemoteContinuationCoverage,
	/// New capture's run and source labels.
	pub epochs: RemoteEpochs,
	/// Fresh SFTP regular-file observation, without stable identity claims.
	pub source: RemoteSourceObservation,
	/// Exact exclusive end of the newly compared and synchronized prefix.
	pub adopted_end: StreamLength,
	/// Fresh ordinary BLAKE3 stream digest through the adopted end.
	pub prefix_digest: StreamDigest,
	/// Current signed download grant's digest as recorded.
	pub grant_digest: [u8; 32],
	/// Strategy-qualified destination record digest as recorded.
	pub qualification_digest: [u8; 32],
}

/// Independently selected exact claims and prior admitted source extent.
///
/// The caller resolves every historical anchor from the actual clean prefix
/// and derives concrete observations from held capabilities before signing.
/// This type carries neither native observations nor mutation authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteContinuationExpectation<'name> {
	/// Exact expected signed claims.
	pub claims: RemoteContinuationClaims<'name>,
	/// Prior writer's bound source length from resolved run history.
	pub prior_source_extent: StreamLength,
}

/// One canonical, context-matched record under an independently selected job owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteCaptureContinued<'frame> {
	claims: RemoteContinuationClaims<'frame>,
	boundary: RemoteReplayBoundary,
}

impl<'frame> RemoteCaptureContinued<'frame> {
	/// Returns the authenticated recorded claims.
	#[must_use]
	pub const fn claims(self) -> RemoteContinuationClaims<'frame> {
		self.claims
	}

	/// Returns the exact observed successor boundary.
	#[must_use]
	pub const fn boundary(self) -> RemoteReplayBoundary {
		self.boundary
	}
}

impl RemoteBootstrapTrust<'_> {
	/// Signs canonical kind-40 recorded evidence under the selected owner key.
	/// # Errors
	/// Refuses mismatched trust, out-of-scope claims or oversized payloads.
	pub fn sign_continuation(
		&self,
		expected: &RemoteContinuationExpectation<'_>,
		signer: &SigningKey,
	) -> Result<Vec<u8>, Error> {
		if signer.verifying_key() != *self.key() {
			return Err(OwnerError::UntrustedKey.into());
		}
		validation::claims(self, &expected.claims, expected.prior_source_extent)?;
		let body = wire::encode_body(&expected.claims)?;
		let signature = signer.sign(&wire::signature_input(&body)?).to_bytes();
		let payload = wire::encode_envelope(&body, &signature)?;
		if successor_offset(expected.claims.previous.offset, payload.len())
			.is_none_or(|end| end > MAX_FIRST_SEGMENT_BYTES)
		{
			return Err(Error::Length);
		}
		Ok(payload)
	}

	/// Authenticates an exact frame relative to independently selected claims.
	///
	/// The caller supplies the actual segment-relative end from the checked
	/// frame reader and resolves the expected extents, anchors and identities.
	/// # Errors
	/// Refuses any kind, boundary, canonical shape, signature or claim mismatch.
	pub fn from_continuation_frame<'frame>(
		&self,
		frame: &'frame Frame,
		observed_end: RemoteReplayBoundary,
		expected: &RemoteContinuationExpectation<'_>,
	) -> Result<RemoteCaptureContinued<'frame>, Error> {
		let recorded = self.verify_continuation_frame(
			frame,
			expected.claims.previous,
			observed_end,
			expected.prior_source_extent,
		)?;
		if recorded.claims != expected.claims {
			return Err(Error::Binding);
		}
		Ok(recorded)
	}

	pub(super) fn verify_continuation_frame<'frame>(
		&self,
		frame: &'frame Frame,
		previous: RemoteReplayBoundary,
		observed_end: RemoteReplayBoundary,
		prior_source_extent: StreamLength,
	) -> Result<RemoteCaptureContinued<'frame>, Error> {
		if frame.kind() != FrameKind::RemoteCaptureContinued
			|| observed_end.head != frame.head()
			|| observed_end.offset > MAX_FIRST_SEGMENT_BYTES
			|| successor_offset(previous.offset, frame.payload().len()) != Some(observed_end.offset)
			|| previous.head.sequence().checked_add(1) != Some(frame.head().sequence())
			|| previous.head.digest() != frame.previous_digest()
		{
			return Err(Error::FrameBinding);
		}
		let (body, signature) = wire::decode_envelope(frame.payload())?;
		let claims = wire::decode_body(body)?;
		self.key()
			.verify_strict(
				&wire::signature_input(body)?,
				&Signature::from_bytes(&signature),
			)
			.map_err(|_| OwnerError::InvalidSignature)?;
		if claims.previous != previous {
			return Err(Error::Binding);
		}
		validation::claims(self, &claims, prior_source_extent)?;
		Ok(RemoteCaptureContinued {
			claims,
			boundary: observed_end,
		})
	}
}

fn successor_offset(previous: u64, payload_len: usize) -> Option<u64> {
	let frame_bytes = u64::try_from(FRAME_OVERHEAD_BYTES.checked_add(payload_len)?).ok()?;
	previous.checked_add(frame_bytes)
}
