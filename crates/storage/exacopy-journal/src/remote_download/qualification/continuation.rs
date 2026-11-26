//! Independently selected V2 qualification for same-inode remote continuation.

use core::fmt;

use ed25519_dalek::{Signature, VerifyingKey};
use exacopy_endpoint::linux_remote_qualification::RemoteDestinationFacts;

use super::{MAX_REMOTE_QUALIFICATION_BYTES, RemoteQualificationError, RemoteQualificationScope};

mod wire;

const RECORD_DOMAIN: &[u8] = b"ExaCopy/linux-remote-destination-qualification-record/v2\0";

/// Operation exercised by a continuation qualification campaign.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteContinuationOperationProfile {
	/// Independently verify a retained prefix, synchronize it, and append only its suffix.
	VerifiedRetainedAppendV1,
}

/// Required independent campaign evidence for a continuation operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteContinuationCoverageProfile {
	/// Every required retained-append case and observed process-crash cut.
	RetainedAppendProcessCrashV1,
}

/// Independently selected scope of one continuation qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteContinuationQualificationScope {
	/// Exact build, route class, campaign definition and reviewed evidence.
	pub common: RemoteQualificationScope,
	/// Exact continuation operation.
	pub operation: RemoteContinuationOperationProfile,
	/// Exact required campaign coverage profile.
	pub coverage: RemoteContinuationCoverageProfile,
}

/// Independent trust selection for this continuation qualification reader.
#[derive(Debug)]
pub struct RemoteContinuationQualificationTrust<'keys> {
	/// Independently configured qualification attestor identity.
	pub attestor: [u8; 16],
	/// Independently configured qualification attestation key.
	pub attestor_key: &'keys VerifyingKey,
	/// Ordinary job-owner verification key, ineligible to attest for this job.
	pub owner_key: &'keys VerifyingKey,
	/// Exact expected V2 claims selected independently of the record.
	pub scope: RemoteContinuationQualificationScope,
}

/// Digest of a verified complete V2 record in its own domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteContinuationQualificationDigest([u8; 32]);

impl RemoteContinuationQualificationDigest {
	/// Returns the value to compare with the historical kind-40 digest.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// Exact verified signature and expected scope, suitable for historical comparison.
///
/// Native facts in this object are signed historical claims. Current effects
/// require independently established native observations and operation authority.
#[derive(Debug)]
pub struct VerifiedRemoteContinuationQualification {
	attestor_key: VerifyingKey,
	owner_key: VerifyingKey,
	scope: RemoteContinuationQualificationScope,
	facts: RemoteDestinationFacts,
	digest: RemoteContinuationQualificationDigest,
}

impl VerifiedRemoteContinuationQualification {
	/// Returns the verified V2 record digest.
	#[must_use]
	pub const fn digest(&self) -> RemoteContinuationQualificationDigest {
		self.digest
	}

	/// Returns the exact independently selected V2 scope.
	#[must_use]
	pub const fn scope(&self) -> RemoteContinuationQualificationScope {
		self.scope
	}

	/// Returns the signed historical facts for matching the selected owner scope.
	#[must_use]
	pub const fn facts(&self) -> &RemoteDestinationFacts {
		&self.facts
	}

	/// Returns the independently selected key that verified the attestation.
	#[must_use]
	pub const fn attestor_key(&self) -> &VerifyingKey {
		&self.attestor_key
	}

	/// Checks that replay or activation uses the exact independently selected owner.
	#[must_use]
	pub fn matches_owner(&self, owner_key: &VerifyingKey) -> bool {
		&self.owner_key == owner_key
	}

	/// Matches the attestation against exact live build and destination observations.
	///
	/// The caller supplies the currently running image measurement and held destination
	/// facts, and maintains their live binding at every required effect boundary.
	/// # Errors
	/// Refuses changed or mismatching build, root, mount, boot or execution facts.
	pub fn match_current<'current>(
		&'current self,
		measured_build: [u8; 32],
		observed: &'current RemoteDestinationFacts,
	) -> Result<
		CurrentRemoteContinuationQualification<'current>,
		RemoteContinuationQualificationError,
	> {
		use RemoteContinuationQualificationError as Error;

		if self.scope.common.build != measured_build {
			return Err(Error::RunningBuild);
		}
		if &self.facts != observed {
			return Err(Error::LiveDestination);
		}
		Ok(CurrentRemoteContinuationQualification {
			verified: self,
			observed,
		})
	}
}

/// Verified continuation qualification matched to independently supplied current facts.
///
/// This projection carries neither an exclusive native lease nor a source grant,
/// append permit, journal acknowledgment or authorization to publish.
#[derive(Debug)]
pub struct CurrentRemoteContinuationQualification<'current> {
	verified: &'current VerifiedRemoteContinuationQualification,
	observed: &'current RemoteDestinationFacts,
}

impl CurrentRemoteContinuationQualification<'_> {
	/// Returns the underlying verified V2 record.
	#[must_use]
	pub const fn verified(&self) -> &VerifiedRemoteContinuationQualification {
		self.verified
	}

	/// Returns the exact currently selected destination observations.
	#[must_use]
	pub const fn facts(&self) -> &RemoteDestinationFacts {
		self.observed
	}
}

/// Refusal of a V2 remote continuation qualification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteContinuationQualificationError {
	/// Envelope, trust, signature, bounded facts or common scope failed verification.
	Evidence(RemoteQualificationError),
	/// The continuation operation profile was unsupported or mismatched.
	Operation,
	/// The required coverage profile or complete case mask was unsupported or mismatched.
	Coverage,
	/// The measured running build differs from the verified record.
	RunningBuild,
	/// Exact current destination facts differ from the verified record.
	LiveDestination,
}

impl From<RemoteQualificationError> for RemoteContinuationQualificationError {
	fn from(error: RemoteQualificationError) -> Self {
		Self::Evidence(error)
	}
}

impl fmt::Display for RemoteContinuationQualificationError {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Evidence(error) => error.fmt(out),
			Self::Operation => out.write_str("invalid remote continuation operation profile"),
			Self::Coverage => out.write_str("invalid or incomplete remote continuation coverage"),
			Self::RunningBuild => {
				out.write_str("current executable differs from continuation qualification")
			}
			Self::LiveDestination => {
				out.write_str("current destination differs from continuation qualification")
			}
		}
	}
}

impl std::error::Error for RemoteContinuationQualificationError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Evidence(error) => Some(error),
			_ => None,
		}
	}
}

/// Verifies bounded V2 bytes under independent attestor trust and expected scope.
///
/// This entry point can verify historical records without live filesystem access.
/// Before selecting the append strategy the application must independently
/// establish the current build and facts, then match them with this result.
/// # Errors
/// Refuses untrusted, unsupported, noncanonical, incomplete or mismatched evidence.
pub fn verify_remote_continuation_qualification(
	record: &[u8],
	trust: &RemoteContinuationQualificationTrust<'_>,
) -> Result<VerifiedRemoteContinuationQualification, RemoteContinuationQualificationError> {
	use RemoteQualificationError as Evidence;

	if record.len() > MAX_REMOTE_QUALIFICATION_BYTES {
		return Err(Evidence::Length.into());
	}
	if trust.attestor == [0; 16]
		|| !is_canonical_strong(trust.attestor_key)
		|| !is_canonical_strong(trust.owner_key)
		|| trust.attestor_key == trust.owner_key
	{
		return Err(Evidence::Trust.into());
	}
	if !trust.scope.common.is_valid() {
		return Err(Evidence::Scope.into());
	}
	let envelope = wire::read_envelope(record)?;
	if envelope.key != trust.attestor_key.to_bytes() {
		return Err(Evidence::Attestor.into());
	}
	let signature = Signature::from_bytes(&envelope.signature);
	wire::with_signature_input(&envelope, |input| {
		trust.attestor_key.verify_strict(input, &signature)
	})?
	.map_err(|_| Evidence::Signature)?;
	let claims = wire::read_claims(envelope.body)?;
	if claims.attestor != trust.attestor {
		return Err(Evidence::Attestor.into());
	}
	if claims.scope.operation != trust.scope.operation {
		return Err(RemoteContinuationQualificationError::Operation);
	}
	if claims.scope.coverage != trust.scope.coverage {
		return Err(RemoteContinuationQualificationError::Coverage);
	}
	if claims.scope.common != trust.scope.common {
		return Err(Evidence::Scope.into());
	}
	let digest = *blake3::Hasher::new()
		.update(RECORD_DOMAIN)
		.update(record)
		.finalize()
		.as_bytes();
	if digest == [0; 32] {
		return Err(Evidence::ReservedDigest.into());
	}
	Ok(VerifiedRemoteContinuationQualification {
		attestor_key: *trust.attestor_key,
		owner_key: *trust.owner_key,
		scope: claims.scope,
		facts: claims.facts,
		digest: RemoteContinuationQualificationDigest(digest),
	})
}

fn is_canonical_strong(key: &VerifyingKey) -> bool {
	!key.is_weak() && key.to_edwards().compress().to_bytes() == key.to_bytes()
}
