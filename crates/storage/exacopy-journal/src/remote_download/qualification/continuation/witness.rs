use ed25519_dalek::VerifyingKey;
use exacopy_endpoint::linux_remote_qualification::RemoteDestinationFacts;

use super::{
	Profile, RemoteContinuationQualificationDigest, RemoteContinuationQualificationError,
	RemoteContinuationQualificationScope, RemoteContinuationQualificationTrust,
	VerifiedRemoteContinuationQualification, verify_profile,
};

/// Historically verified attestation for the exact witnessed retained-append profile.
///
/// Only the witness-specific verifier constructs this projection. It describes a
/// signed qualification and carries no approval to retain a link or other effect.
#[derive(Debug)]
pub struct VerifiedRemoteWitnessQualification(VerifiedRemoteContinuationQualification);

impl VerifiedRemoteWitnessQualification {
	/// Returns the digest to compare with the exact selected kind-40 declaration.
	#[must_use]
	pub const fn digest(&self) -> RemoteContinuationQualificationDigest {
		self.0.digest()
	}

	/// Returns the exact independently selected witnessed operation and coverage.
	#[must_use]
	pub const fn scope(&self) -> RemoteContinuationQualificationScope {
		self.0.scope()
	}

	/// Returns signed historical destination facts.
	#[must_use]
	pub const fn facts(&self) -> &RemoteDestinationFacts {
		self.0.facts()
	}

	/// Returns the trusted attestor key used to verify this record.
	#[must_use]
	pub const fn attestor_key(&self) -> &VerifyingKey {
		self.0.attestor_key()
	}

	/// Checks the exact independently selected owner key.
	#[must_use]
	pub fn matches_owner(&self, owner_key: &VerifyingKey) -> bool {
		self.0.matches_owner(owner_key)
	}

	/// Matches exact independently observed current facts and running build.
	///
	/// # Errors
	/// Refuses a different measured build or different native destination facts.
	pub fn match_current<'current>(
		&'current self,
		measured_build: [u8; 32],
		observed: &'current RemoteDestinationFacts,
	) -> Result<CurrentRemoteWitnessQualification<'current>, RemoteContinuationQualificationError>
	{
		self.0.match_current(measured_build, observed)?;
		Ok(CurrentRemoteWitnessQualification {
			verified: self,
			observed,
		})
	}
}

/// Witness-specific qualification matched to independent current observations.
///
/// Witness retention, grant, native lease, write and publication capabilities
/// require separate admission.
#[derive(Debug)]
pub struct CurrentRemoteWitnessQualification<'current> {
	verified: &'current VerifiedRemoteWitnessQualification,
	observed: &'current RemoteDestinationFacts,
}

impl CurrentRemoteWitnessQualification<'_> {
	/// Returns the exact historically verified witnessed qualification.
	#[must_use]
	pub const fn verified(&self) -> &VerifiedRemoteWitnessQualification {
		self.verified
	}

	/// Returns the exact observed current destination facts used for the match.
	#[must_use]
	pub const fn facts(&self) -> &RemoteDestinationFacts {
		self.observed
	}
}

/// Verifies the exact separately selected witnessed retained-append V2 attestation.
///
/// The verifier only accepts operation 2 and coverage 2 with the complete
/// 24-case mask. Current build and destination checks are separate.
/// # Errors
/// Refuses other, incomplete, untrusted, noncanonical or mismatched records.
pub fn verify_remote_witness_qualification(
	record: &[u8],
	trust: &RemoteContinuationQualificationTrust<'_>,
) -> Result<VerifiedRemoteWitnessQualification, RemoteContinuationQualificationError> {
	verify_profile(record, trust, Profile::Witness).map(VerifiedRemoteWitnessQualification)
}
