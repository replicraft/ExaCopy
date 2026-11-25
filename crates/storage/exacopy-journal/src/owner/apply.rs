use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::{JournalEntryId, JournalEpoch, RootCapabilityId, StreamLength};

use super::apply_codec;
use super::codec::{self, Envelope, OwnerDomain};
use super::{
	MAX_OWNER_BYTES, OwnerDigest, OwnerError, OwnerManifest, OwnerProfileId, OwnerTimestamp,
};

const DOMAIN: OwnerDomain = OwnerDomain::LinuxPublicApply;

mod identifiers;

pub use identifiers::{
	ApplyMetadataPolicyDigest, ApprovedPublicPlanDigest, ApprovedStreamDigest, PublicPlanEntryId,
};

/// The requested minimum durability admitted by the initial public-apply owner form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyRequestedDurability {
	/// The plan requests process-crash durability; this is no claim about achieved guarantees.
	ProcessCrash,
}

/// Public approval claims that must remain attached to a private Linux copy job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicApplyBinding {
	/// The digest of the approved canonical public Plan body.
	pub public_plan: ApprovedPublicPlanDigest,
	/// The exact approved entry in the referenced page.
	pub public_entry: PublicPlanEntryId,
	/// The entry in the private copy plan and journal.
	pub private_entry: JournalEntryId,
	/// The nonzero epoch of the private copy plan.
	pub epoch: JournalEpoch,
	/// The admitted local source-root alias.
	pub source_root: RootCapabilityId,
	/// The admitted local destination-root alias.
	pub destination_root: RootCapabilityId,
	/// The approved length of the one unnamed stream.
	pub stream_length: StreamLength,
	/// The approved ordinary BLAKE3 digest of that stream.
	pub stream_digest: ApprovedStreamDigest,
	/// The digest of the approved versioned metadata policy.
	pub metadata_policy: ApplyMetadataPolicyDigest,
	/// The last boundary for a new effect. A finite expiry is exclusive.
	pub expires_at: Option<OwnerTimestamp>,
	/// Minimum requested durability for the approved effect.
	pub requested_durability: ApplyRequestedDurability,
}

/// Caller-supplied claims for a public Plan applied through a private Linux copy.
///
/// The inner manifest's `created` is the recorded admission time. Its
/// `plan_digest` remains exclusively in the private copy plan digest domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicApplyOwnerManifest {
	/// Private job, profile, state and private plan claims.
	pub owner: OwnerManifest,
	/// Public approval and private attempt claims authenticated together.
	pub binding: PublicApplyBinding,
}

impl PublicApplyOwnerManifest {
	pub(super) fn validate(&self) -> Result<(), OwnerError> {
		self.owner.validate()?;
		if self.binding.private_entry.as_bytes() == &[0; 16] {
			return Err(OwnerError::InvalidApplyEntry);
		}
		if self.binding.epoch.get() == 0 {
			return Err(OwnerError::InvalidApplyEpoch);
		}
		if self.binding.expires_at.is_some_and(|expiry| {
			let admitted = self.owner.created;
			(expiry.seconds(), expiry.nanoseconds()) <= (admitted.seconds(), admitted.nanoseconds())
		}) {
			return Err(OwnerError::InvalidApplyExpiry);
		}
		Ok(())
	}
}

/// Authenticated, immutable local evidence of the approved public/private Plan binding.
///
/// This record is a distinct mandatory owner form. Ordinary Linux and managed
/// APFS owner readers refuse it. Authentication verifies the selected profile's
/// declaration. The coordinator separately checks actual Plan semantics, live
/// identities, observed stream, durable journal context and trusted clock.
#[derive(Eq, PartialEq)]
pub struct PublicApplyOwnerRecord {
	manifest: PublicApplyOwnerManifest,
	bytes: Vec<u8>,
}

impl PublicApplyOwnerRecord {
	/// Signs a declaration using the independently selected local profile key.
	///
	/// # Errors
	/// Refuses invalid, oversized or unsupported owner claims.
	pub fn sign(
		manifest: PublicApplyOwnerManifest,
		profile_key: &SigningKey,
	) -> Result<Self, OwnerError> {
		manifest.validate()?;
		let verifying_key = profile_key.verifying_key();
		if verifying_key.is_weak() {
			return Err(OwnerError::InvalidSignature);
		}
		let public_key = verifying_key.to_bytes();
		let encoded_body = apply_codec::encode_body(&manifest, &public_key)?;
		let body = codec::encoded_bytes(&encoded_body);
		let signature = profile_key
			.try_sign(&DOMAIN.signature_input(body))
			.map_err(|_| OwnerError::InvalidSignature)?;
		let envelope = Envelope {
			body,
			public_key,
			signature: signature.to_bytes(),
		};
		let encoded = codec::encode_envelope(&envelope, DOMAIN)?;
		Ok(Self {
			manifest,
			bytes: codec::encoded_bytes(&encoded).to_vec(),
		})
	}

	/// Decodes against an independently selected local profile ID and key.
	///
	/// Stored expiry remains inspectable, including after it passes. Effect
	/// admission requires a separate check against the caller's trusted time.
	///
	/// # Errors
	/// Refuses oversized, unsupported, noncanonical or unauthenticated evidence.
	pub fn decode(
		bytes: &[u8],
		expected_profile: OwnerProfileId,
		expected_key: &VerifyingKey,
	) -> Result<Self, OwnerError> {
		if bytes.len() > MAX_OWNER_BYTES {
			return Err(OwnerError::Length);
		}
		let envelope = codec::decode_envelope(bytes, DOMAIN)?;
		let public_key = expected_key.to_bytes();
		if envelope.public_key != public_key {
			return Err(OwnerError::UntrustedKey);
		}
		let signature = Signature::from_bytes(&envelope.signature);
		expected_key
			.verify_strict(&DOMAIN.signature_input(envelope.body), &signature)
			.map_err(|_| OwnerError::InvalidSignature)?;
		let manifest = apply_codec::decode_body(envelope.body, &public_key)?;
		if manifest.owner.profile != expected_profile {
			return Err(OwnerError::UntrustedProfile);
		}
		Ok(Self {
			manifest,
			bytes: bytes.to_vec(),
		})
	}

	/// Returns the signed private-job and public-approval claims.
	#[must_use]
	pub const fn manifest(&self) -> &PublicApplyOwnerManifest {
		&self.manifest
	}

	/// Returns the entire canonical signed envelope for owner-private persistence.
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		&self.bytes
	}

	/// Computes the digest of this entire envelope to bind in the initial journal record.
	#[must_use]
	pub fn digest(&self) -> OwnerDigest {
		OwnerDigest::from_bytes(*blake3::hash(self.as_bytes()).as_bytes())
	}
}

impl fmt::Debug for PublicApplyOwnerRecord {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("PublicApplyOwnerRecord")
			.field("manifest", &self.manifest)
			.finish_non_exhaustive()
	}
}
