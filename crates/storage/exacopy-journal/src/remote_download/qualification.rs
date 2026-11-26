//! Authentication of independently selected Linux remote destination qualification.

use std::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use exacopy_endpoint::linux_remote_qualification::{
	RemoteDestinationFacts, RemoteDestinationQualification,
};
use minicbor::encode::{self, write::EndOfArray};

use super::RemoteDownloadError;

pub mod continuation;
mod wire;

const RECORD_DOMAIN: &[u8] = b"ExaCopy/linux-remote-destination-qualification-record/v1\0";

/// Maximum complete signed qualification record bytes.
///
/// Covers the bounded raw mountinfo and kernel fields, route, claims and signature.
pub const MAX_REMOTE_QUALIFICATION_BYTES: usize = 3072;

/// Transport profile class exercised by the destination qualification campaign.
///
/// Source authority, endpoint, peer identity and route revision remain separately
/// checked against the selected remote download owner and grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteQualificationRouteClass {
	/// Agentless SFTP over directly dialed, pinned TCP.
	DirectPinnedTcpV1,
	/// Agentless SFTP over TCP inside the admitted embedded WireGuard route.
	EmbeddedWireGuardTcpV1,
}

/// Independently chosen build, route and campaign inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteQualificationScope {
	/// Digest identifying the exact currently selected tested build.
	pub build: [u8; 32],
	/// Exact transport profile class selected and tested for this campaign.
	pub route: RemoteQualificationRouteClass,
	/// Digest of the independently selected campaign definition and scope.
	pub campaign_scope: [u8; 32],
	/// Digest of the complete, independently reviewed campaign evidence.
	pub campaign_evidence: [u8; 32],
}

impl RemoteQualificationScope {
	fn is_valid(self) -> bool {
		![self.build, self.campaign_scope, self.campaign_evidence].contains(&[0; 32])
	}
}

/// Trust inputs selected outside the qualification record and ordinary job owner's authority.
#[derive(Debug)]
pub struct RemoteQualificationTrust<'keys> {
	/// Independently configured qualification attestor identity.
	pub attestor: [u8; 16],
	/// Independently configured qualification attestation public key.
	pub attestor_key: &'keys VerifyingKey,
	/// The selected ordinary job-owner verification key, excluded from this role.
	pub owner_key: &'keys VerifyingKey,
	/// Exact independently selected build, route and campaign claims.
	pub scope: RemoteQualificationScope,
}

/// Why a private qualification record was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteQualificationError {
	/// The record or a fixed field exceeded its encoding bounds.
	Length,
	/// The versioned record has an invalid wire shape or field order.
	Shape,
	/// The record or claims are not canonically encoded.
	NonCanonical,
	/// The qualification record version is unsupported.
	Version,
	/// The record does not declare the qualification attestation role.
	Role,
	/// Expected trust is invalid, weak, or uses the selected ordinary owner key.
	Trust,
	/// The attestor identity or public key differs from independent selection.
	Attestor,
	/// Signature verification failed in the qualification-specific domain.
	Signature,
	/// The tested build, route, campaign scope or complete evidence digest differs.
	Scope,
	/// A physical destination fact is invalid or differs from fresh native evidence.
	DestinationFacts,
	/// The complete record digest matched the reserved zero value.
	ReservedDigest,
}

impl fmt::Display for RemoteQualificationError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Length => "remote qualification record exceeds its encoding bounds",
			Self::Shape => "invalid remote qualification wire shape",
			Self::NonCanonical => "remote qualification encoding is not canonical",
			Self::Version => "unsupported remote qualification version",
			Self::Role => "wrong remote qualification signing role",
			Self::Trust => "invalid or nonindependent remote qualification trust",
			Self::Attestor => "remote qualification does not match the trusted attestor",
			Self::Signature => "remote qualification signature verification failed",
			Self::Scope => "remote qualification does not match the selected campaign scope",
			Self::DestinationFacts => "remote qualification does not match the destination facts",
			Self::ReservedDigest => "remote qualification uses the reserved zero record digest",
		})
	}
}

impl std::error::Error for RemoteQualificationError {}

impl From<RemoteDownloadError> for RemoteQualificationError {
	fn from(cause: RemoteDownloadError) -> Self {
		match cause {
			RemoteDownloadError::Length => Self::Length,
			_ => Self::Shape,
		}
	}
}

impl From<minicbor::decode::Error> for RemoteQualificationError {
	fn from(_: minicbor::decode::Error) -> Self {
		Self::Shape
	}
}

impl From<encode::Error<EndOfArray>> for RemoteQualificationError {
	fn from(_: encode::Error<EndOfArray>) -> Self {
		Self::Length
	}
}

/// Authenticates the exact selected qualification and projects it for native admission.
///
/// The caller selects the trust, reviewed campaign and build from independent
/// configuration and supplies facts observed from the currently held destination.
/// A verified projection describes an attestation. Native identity, synchronization,
/// and eligibility for an effect must still come from the destination adapter.
///
/// # Errors
/// Refuses noncanonical or unsupported records, independent trust and scope mismatches,
/// and any difference from the provided exact destination facts.
pub fn verify_remote_destination_qualification(
	record: &[u8],
	trust: &RemoteQualificationTrust<'_>,
	observed: &RemoteDestinationFacts,
) -> Result<RemoteDestinationQualification, RemoteQualificationError> {
	use RemoteQualificationError as Error;

	if record.len() > MAX_REMOTE_QUALIFICATION_BYTES {
		return Err(Error::Length);
	}
	if trust.attestor == [0; 16]
		|| trust.attestor_key == trust.owner_key
		|| trust.attestor_key.is_weak()
		|| trust.owner_key.is_weak()
	{
		return Err(Error::Trust);
	}
	if !trust.scope.is_valid() {
		return Err(Error::Scope);
	}
	let envelope = wire::read_envelope(record)?;
	if envelope.key != trust.attestor_key.to_bytes() {
		return Err(Error::Attestor);
	}
	trust
		.attestor_key
		.verify_strict(
			&wire::signature_input(&envelope)?,
			&Signature::from_bytes(&envelope.signature),
		)
		.map_err(|_| Error::Signature)?;
	let claims = wire::read_claims(envelope.body)?;
	if claims.attestor != trust.attestor {
		return Err(Error::Attestor);
	}
	if claims.scope != trust.scope {
		return Err(Error::Scope);
	}
	if &claims.facts != observed {
		return Err(Error::DestinationFacts);
	}
	let digest = *blake3::Hasher::new()
		.update(RECORD_DOMAIN)
		.update(record)
		.finalize()
		.as_bytes();
	RemoteDestinationQualification::new(claims.facts, digest).ok_or(Error::ReservedDigest)
}
