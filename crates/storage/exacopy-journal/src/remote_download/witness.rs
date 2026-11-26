//! Bounded selector-2 records for a protected witness and pending receipt.
//!
//! These records bind historical evidence. They do not admit live consent,
//! authenticate native observations or authorize effects. The caller resolves
//! the authoritative lineage and phase from the selected journal history.

use std::num::NonZeroU64;

use ed25519_dalek::{Signature, Signer, SigningKey};
use exacopy_endpoint::linux_job::JobFileIdentity;

use crate::frame::{ChainHead, FRAME_OVERHEAD_BYTES, Frame, FrameKind};
use crate::{LinuxFileIdentity, MAX_FIRST_SEGMENT_BYTES, OwnerError, StreamLength};

use super::continuation::RemoteCaptureContinued;
use super::continuation::checkpoint::RemoteContinuedCheckpoint;
use super::continuation::replay::RemoteWitnessCoveragePredecessor;
use super::qualification::RemoteQualificationRouteClass;
use super::qualification::continuation::VerifiedRemoteWitnessQualification;
use super::replay::RemoteReplayBoundary;
use super::{
	RemoteBootstrapTrust, RemoteDownloadContext, RemoteDownloadError as Error, RemoteDownloadRoute,
	RemoteEpochs, RemoteScopeDigest,
};

pub mod budget;
mod receipt_ready;
pub mod records;
pub mod replay;
mod wire;

pub use receipt_ready::{
	MAX_REMOTE_WITNESS_RECEIPT_BYTES, ReceiptReadyExpectation, RemoteReceiptReady,
};

/// Exact maximum of canonical kind 41, including its signed envelope.
pub const MAX_REMOTE_WITNESS_INTENT_BYTES: usize = 605;
/// Exact maximum of canonical kind 42.
pub const MAX_REMOTE_RECEIPT_READY_BYTES: usize = 689;

const WITNESS_INTENT_DOMAIN: &[u8] = b"ExaCopy/linux-remote-witness-intent/v1\0";

/// Fixed final coverage of the new run selected before witnessed closeout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteWitnessCoverage {
	/// The active declaration already covers the complete source.
	ContinuedPrefix {
		/// Exact kind-40 head.
		head: ChainHead,
		/// Exclusive end of the adopted prefix.
		end: StreamLength,
	},
	/// The actual last continued checkpoint reaches the complete source extent.
	Checkpoint {
		/// Exact terminal continued kind-3 head.
		head: ChainHead,
		/// One-based ordinal within the continued run.
		ordinal: u16,
		/// Exclusive end of the new coverage.
		end: StreamLength,
	},
}

/// Exact selected lineage repeated unchanged through witnessed closeout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteWitnessBinding {
	context: RemoteDownloadContext,
	scope: RemoteScopeDigest,
	allocation: ChainHead,
	prepared: ChainHead,
	continuation: ChainHead,
	epochs: RemoteEpochs,
	stage: LinuxFileIdentity,
	coverage: RemoteWitnessCoverage,
}

impl RemoteWitnessBinding {
	/// Returns the active signed continuation head.
	#[must_use]
	pub const fn continuation(self) -> ChainHead {
		self.continuation
	}

	/// Returns the active declaration's job-wide epochs.
	#[must_use]
	pub const fn epochs(self) -> RemoteEpochs {
		self.epochs
	}

	/// Returns the inherited private stage inode identity as recorded.
	#[must_use]
	pub const fn stage(self) -> LinuxFileIdentity {
		self.stage
	}

	/// Returns the exact same-pass coverage declaration.
	#[must_use]
	pub const fn coverage(self) -> RemoteWitnessCoverage {
		self.coverage
	}
}

/// Historical owner consent expected for this exact witness observation.
///
/// Digest equality binds this expectation to the selected owner/job/scope and
/// base grant. This value carries no live authorization or clock observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessRetentionCommitment {
	/// Exact separately selected grant digest.
	pub base_grant_digest: [u8; 32],
	/// Exact expected digest of the recorded owner consent projection.
	pub approval_digest: [u8; 32],
	/// Positive exclusive POSIX expiration in seconds.
	pub deadline: NonZeroU64,
}

impl WitnessRetentionCommitment {
	/// Computes the canonical digest of the selector-2 consent projection.
	///
	/// The caller is responsible for proving actual approval before signing
	/// its recorded commitment. This function performs no clock check.
	///
	/// # Errors
	/// Refuses zero scope, grant or context digest or a nil entry.
	pub fn measure(
		context: RemoteDownloadContext,
		scope: RemoteScopeDigest,
		base_grant_digest: [u8; 32],
		deadline: NonZeroU64,
	) -> Result<Self, Error> {
		Ok(Self {
			base_grant_digest,
			approval_digest: wire::approval_digest(context, scope, base_grant_digest, deadline)?,
			deadline,
		})
	}
}

/// Exact history and observations the caller resolved independently for kind 41.
#[derive(Debug)]
pub struct RemoteWitnessIntentExpectation<'history> {
	/// Complete terminal coverage borrowed from the exact witnessed scan.
	pub coverage: RemoteWitnessCoveragePredecessor<'history>,
	/// Selected witness-specific destination attestation.
	pub qualification: &'history VerifiedRemoteWitnessQualification,
	/// Independently resolved native stage directory.
	pub stage_directory: LinuxFileIdentity,
	/// Independently resolved protected job root.
	pub job_directory: LinuxFileIdentity,
	/// Exact independently selected historical approval commitment.
	pub consent: WitnessRetentionCommitment,
}

/// Canonical, owner-authenticated kind 41 in the selected closeout lineage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteWitnessIntent {
	binding: RemoteWitnessBinding,
	boundary: RemoteReplayBoundary,
	stage_directory: LinuxFileIdentity,
	job_directory: LinuxFileIdentity,
	nonce: [u8; 16],
	target_parent: LinuxFileIdentity,
	qualification_digest: [u8; 32],
	consent: WitnessRetentionCommitment,
}

impl RemoteWitnessIntent {
	/// Returns the fixed lineage and coverage repeated by later closeout records.
	#[must_use]
	pub const fn binding(self) -> RemoteWitnessBinding {
		self.binding
	}

	/// Returns the accepted end of the exact signed record.
	#[must_use]
	pub const fn boundary(self) -> RemoteReplayBoundary {
		self.boundary
	}

	/// Returns the expected protected job directory identity.
	#[must_use]
	pub const fn job_directory(self) -> LinuxFileIdentity {
		self.job_directory
	}

	/// Returns the exact witness basename committed by the authenticated record.
	///
	/// Current custody and permission to create or inspect the name are separate.
	#[must_use]
	pub fn witness_name(self) -> [u8; 40] {
		wire::witness_name(self.nonce)
	}

	/// Returns the consent committed by the signed record.
	#[must_use]
	pub const fn consent(self) -> WitnessRetentionCommitment {
		self.consent
	}
}

impl RemoteBootstrapTrust<'_> {
	/// Signs the exact caller-selected recorded kind-41 commitments.
	///
	/// Signing requires prior independent native and live-consent admission
	/// by the caller. The signed payload itself supplies neither.
	///
	/// # Errors
	/// Refuses wrong key, context, coverage, consent or offset bounds.
	pub fn sign_witness_intent(
		&self,
		expected: &RemoteWitnessIntentExpectation<'_>,
		signer: &SigningKey,
	) -> Result<Vec<u8>, Error> {
		if signer.verifying_key() != *self.key() {
			return Err(OwnerError::UntrustedKey.into());
		}
		let record = resolve(self, expected)?;
		let claims = wire::witness_claims(record, expected.coverage.boundary().head)?;
		let sig = signer.sign(&wire::signature_input(&claims)?).to_bytes();
		let payload = wire::witness_envelope(&claims, &sig)?;
		successor_end(expected.coverage.boundary(), payload.len())?;
		Ok(payload)
	}

	/// Authenticates exactly the caller-selected historical witness commitments.
	///
	/// # Errors
	/// Refuses wrong frame chain, bounds, shape, owner signature or selected facts.
	pub fn from_witness_intent_frame(
		&self,
		frame: &Frame,
		end: RemoteReplayBoundary,
		expected: &RemoteWitnessIntentExpectation<'_>,
	) -> Result<RemoteWitnessIntent, Error> {
		check_successor(
			frame,
			FrameKind::RemoteWitnessIntent,
			expected.coverage.boundary(),
			end,
		)?;
		let (claims, sig) = wire::read_witness_envelope(frame.payload())?;
		let mut record = resolve(self, expected)?;
		if wire::witness_claims(record, expected.coverage.boundary().head)? != claims {
			return Err(Error::Binding);
		}
		self.key()
			.verify_strict(
				&wire::signature_input(claims)?,
				&Signature::from_bytes(&sig),
			)
			.map_err(|_| OwnerError::InvalidSignature)?;
		record.boundary = end;
		Ok(record)
	}
}

fn resolve(
	trust: &RemoteBootstrapTrust<'_>,
	expected: &RemoteWitnessIntentExpectation<'_>,
) -> Result<RemoteWitnessIntent, Error> {
	let (continuation, predecessor) = expected.coverage.authenticated(trust)?;
	let active = continuation.claims();
	let owner = trust.owner().manifest();
	let parent = owner.scope.destination.parent();
	let selected_route = route_class(owner.scope.source.route())?;
	let native_parent = JobFileIdentity {
		device: parent.device(),
		inode: parent.inode(),
	};
	if !expected.qualification.matches_owner(trust.key())
		|| expected.qualification.scope().common.route != selected_route
		|| expected.qualification.facts().ids().root != native_parent
		|| expected.qualification.digest().as_bytes() != &active.qualification_digest
		|| active.context != RemoteDownloadContext::for_owner(trust.owner())
		|| active.scope != owner.scope.digest()?
		|| active.grant_digest != expected.consent.base_grant_digest
		|| active.directory != expected.stage_directory
		|| owner.job_directory != expected.job_directory
		|| !distinct_on_device([
			parent,
			expected.job_directory,
			active.directory,
			active.stage,
		])
		|| expected.consent
			!= WitnessRetentionCommitment::measure(
				active.context,
				active.scope,
				active.grant_digest,
				expected.consent.deadline,
			)? {
		return Err(Error::Binding);
	}
	let boundary = expected.coverage.boundary();
	let binding = binding_for(continuation, predecessor, boundary)?;
	if binding.coverage.end() != active.source.length() {
		return Err(Error::Binding);
	}
	Ok(RemoteWitnessIntent {
		binding,
		boundary,
		stage_directory: active.directory,
		job_directory: expected.job_directory,
		nonce: active.prior.nonce,
		target_parent: parent,
		qualification_digest: active.qualification_digest,
		consent: expected.consent,
	})
}

fn binding_for(
	continuation: RemoteCaptureContinued<'_>,
	predecessor: &Frame,
	boundary: RemoteReplayBoundary,
) -> Result<RemoteWitnessBinding, Error> {
	let active = continuation.claims();
	Ok(RemoteWitnessBinding {
		context: active.context,
		scope: active.scope,
		allocation: active.prior.allocation,
		prepared: active.prior.prepared,
		continuation: continuation.boundary().head,
		epochs: active.epochs,
		stage: active.stage,
		coverage: coverage(continuation, predecessor, boundary)?,
	})
}

impl RemoteWitnessCoverage {
	const fn end(self) -> StreamLength {
		match self {
			Self::ContinuedPrefix { end, .. } | Self::Checkpoint { end, .. } => end,
		}
	}
}

fn route_class(route: RemoteDownloadRoute) -> Result<RemoteQualificationRouteClass, Error> {
	match route {
		RemoteDownloadRoute::ResolvedDirect { .. } => {
			Ok(RemoteQualificationRouteClass::DirectPinnedTcpV1)
		}
		RemoteDownloadRoute::EmbeddedWireGuard { .. } => {
			Ok(RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1)
		}
		RemoteDownloadRoute::Direct => Err(Error::Scope),
	}
}

fn coverage(
	continuation: RemoteCaptureContinued<'_>,
	frame: &Frame,
	boundary: RemoteReplayBoundary,
) -> Result<RemoteWitnessCoverage, Error> {
	let active = continuation.claims();
	let continued = continuation.boundary();
	if boundary.head != frame.head() || boundary.offset > MAX_FIRST_SEGMENT_BYTES {
		return Err(Error::FrameBinding);
	}
	if frame.kind() == FrameKind::RemoteCaptureContinued {
		if boundary != continued {
			return Err(Error::FrameBinding);
		}
		return Ok(RemoteWitnessCoverage::ContinuedPrefix {
			head: frame.head(),
			end: active.adopted_end,
		});
	}
	let checkpoint = RemoteContinuedCheckpoint::from_frame(frame)?;
	let range = checkpoint.range();
	let end = range
		.offset
		.checked_add(range.length)
		.filter(|&end| end <= active.source.length().get())
		.and_then(|end| StreamLength::new(end).ok())
		.ok_or(Error::Binding)?;
	let checkpoint_bytes =
		u64::try_from(FRAME_OVERHEAD_BYTES + frame.payload().len()).map_err(|_| Error::Length)?;
	let begin = boundary
		.offset
		.checked_sub(checkpoint_bytes)
		.ok_or(Error::FrameBinding)?;
	if checkpoint.context() != active.context
		|| checkpoint.epochs() != active.epochs
		|| checkpoint.continuation() != continued.head
		|| range.offset < active.adopted_end.get()
		|| (range.ordinal == 1
			&& (range.offset != active.adopted_end.get() || begin != continued.offset))
		|| (range.ordinal > 1 && begin <= continued.offset)
	{
		return Err(Error::FrameBinding);
	}
	Ok(RemoteWitnessCoverage::Checkpoint {
		head: frame.head(),
		ordinal: range.ordinal,
		end,
	})
}

fn distinct_on_device<const N: usize>(ids: [LinuxFileIdentity; N]) -> bool {
	ids.iter().enumerate().all(|(index, identity)| {
		identity.inode() != 0
			&& identity.device() == ids[0].device()
			&& !ids[..index].contains(identity)
	})
}

fn successor_end(previous: RemoteReplayBoundary, bytes: usize) -> Result<u64, Error> {
	let frame_size = FRAME_OVERHEAD_BYTES
		.checked_add(bytes)
		.ok_or(Error::Length)?;
	let end = previous
		.offset
		.checked_add(u64::try_from(frame_size).map_err(|_| Error::Length)?)
		.filter(|&end| end <= MAX_FIRST_SEGMENT_BYTES)
		.ok_or(Error::Length)?;
	if previous.offset == 0
		|| previous.head == ChainHead::start()
		|| previous.head.sequence().checked_add(1).is_none()
	{
		return Err(Error::FrameBinding);
	}
	Ok(end)
}

fn check_successor(
	frame: &Frame,
	kind: FrameKind,
	previous: RemoteReplayBoundary,
	end: RemoteReplayBoundary,
) -> Result<(), Error> {
	if frame.kind() != kind
		|| end.head != frame.head()
		|| frame.previous_digest() != previous.head.digest()
		|| previous.head.sequence().checked_add(1) != Some(end.head.sequence())
		|| successor_end(previous, frame.payload().len())? != end.offset
	{
		return Err(Error::FrameBinding);
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn refuses_unresolved_direct_and_selects_resolved_direct() {
		assert_eq!(route_class(RemoteDownloadRoute::Direct), Err(Error::Scope));
		assert_eq!(
			route_class(RemoteDownloadRoute::ResolvedDirect {
				endpoint: "192.0.2.1:22".parse().unwrap()
			}),
			Ok(RemoteQualificationRouteClass::DirectPinnedTcpV1),
		);
	}
}
