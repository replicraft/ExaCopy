use std::fmt;
use std::num::NonZeroU32;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::{JournalJobId, PlanDigest};

use super::codec::{self, Envelope, OwnerDomain};
use super::darwin_codec;
use super::{
	DarwinFileIdentity, DarwinVolumeIdentity, MAX_OWNER_BYTES, OwnerDigest, OwnerError,
	OwnerProfileId, OwnerTimestamp, OwnerToken,
};

const DOMAIN: OwnerDomain = OwnerDomain::DarwinManagedApfs;
// Darwin's sys/syslimits.h defines UID_MAX as 2147483647U.
const DARWIN_UID_MAX: u32 = 2_147_483_647;

/// Caller-supplied owner claims for the managed APFS preserve profile.
///
/// Constructing a manifest leaves the claims unsigned and unauthenticated.
///
/// The profile fixes the private directories to `journal`, `receipts`,
/// and `stage`, in this order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DarwinOwnerManifest {
	/// The independent per-job owner token.
	pub token: OwnerToken,
	/// The durable UUIDv7 job being described.
	pub job: JournalJobId,
	/// The profile that submitted the job.
	pub profile: OwnerProfileId,
	/// The wall clock at creation.
	pub created: OwnerTimestamp,
	/// The destination volume observation from the held capability.
	pub destination_volume: DarwinVolumeIdentity,
	/// The observed identity of the owner-private job directory.
	pub state_root: DarwinFileIdentity,
	/// The job directory owner's UID in `1..=2_147_483_647` (Darwin's `UID_MAX`).
	/// Signing checks the upper bound.
	pub state_root_uid: NonZeroU32,
	/// The canonical plan digest recorded by the originator.
	pub plan_digest: PlanDigest,
}

impl DarwinOwnerManifest {
	pub(super) fn validate(&self) -> Result<(), OwnerError> {
		if self.token.as_bytes() == self.job.as_bytes()
			|| self.token.as_bytes() == self.profile.as_bytes()
		{
			return Err(OwnerError::InvalidToken);
		}
		if self.state_root_uid.get() > DARWIN_UID_MAX {
			return Err(OwnerError::InvalidOwnerUid);
		}
		if self.state_root.volume() != self.destination_volume {
			return Err(OwnerError::DarwinVolumeMismatch);
		}
		Ok(())
	}
}

/// Immutable signed owner evidence for a managed APFS preserve-mode job.
///
/// Recovery must validate live ownership, containment, identities and journal
/// bindings separately before using these authenticated claims.
#[derive(Eq, PartialEq)]
pub struct DarwinOwnerRecord {
	manifest: DarwinOwnerManifest,
	verifying_key: VerifyingKey,
	bytes: Vec<u8>,
}

impl DarwinOwnerRecord {
	/// Signs the manifest with the supplied Darwin profile signing key.
	///
	/// The caller selects the signing key and the manifest's profile ID from
	/// local trusted configuration. The caller also supplies an independent
	/// random owner token and the live observations in the manifest.
	///
	/// # Errors
	/// Refuses invalid claims and unsupported signing keys.
	pub fn sign(
		manifest: DarwinOwnerManifest,
		profile_key: &SigningKey,
	) -> Result<Self, OwnerError> {
		manifest.validate()?;
		let verifying_key = profile_key.verifying_key();
		if verifying_key.is_weak() {
			return Err(OwnerError::InvalidSignature);
		}
		let public_key = verifying_key.to_bytes();
		let encoded_body = darwin_codec::encode_body(&manifest, &public_key)?;
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
			verifying_key,
			bytes: codec::encoded_bytes(&encoded).to_vec(),
		})
	}

	/// Authenticates a canonical envelope against the selected Darwin profile.
	///
	/// The caller supplies the expected profile ID and verification key from
	/// local trusted configuration chosen independently of the envelope.
	///
	/// # Errors
	/// Refuses out-of-profile, oversized, noncanonical or unauthenticated evidence.
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
		let manifest = darwin_codec::decode_body(envelope.body, &public_key)?;
		if manifest.profile != expected_profile {
			return Err(OwnerError::UntrustedProfile);
		}
		let signature = Signature::from_bytes(&envelope.signature);
		expected_key
			.verify_strict(&DOMAIN.signature_input(envelope.body), &signature)
			.map_err(|_| OwnerError::InvalidSignature)?;
		Ok(Self {
			manifest,
			verifying_key: *expected_key,
			bytes: bytes.to_vec(),
		})
	}

	/// Borrows the authenticated signed claims.
	#[must_use]
	pub const fn manifest(&self) -> &DarwinOwnerManifest {
		&self.manifest
	}

	/// Borrows the verification key derived from the supplied signer or supplied
	/// from trusted configuration when decoding.
	#[must_use]
	pub const fn verifying_key(&self) -> &VerifyingKey {
		&self.verifying_key
	}

	/// Borrows the canonical signed bytes for owner-private persistence.
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		&self.bytes
	}

	/// Computes the owner digest to bind in the initial journal record.
	#[must_use]
	pub fn digest(&self) -> OwnerDigest {
		OwnerDigest::from_bytes(*blake3::hash(self.as_bytes()).as_bytes())
	}
}

impl fmt::Debug for DarwinOwnerRecord {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("DarwinOwnerRecord")
			.field("manifest", &self.manifest)
			.field("verifying_key", &self.verifying_key)
			.finish_non_exhaustive()
	}
}
