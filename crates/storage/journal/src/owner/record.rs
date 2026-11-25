use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::codec::{self, Envelope};
use super::{OwnerError, OwnerManifest, OwnerProfileId};

/// The on-disk byte ceiling for one complete signed `owner.cbor` envelope.
pub const MAX_OWNER_BYTES: usize = 64 * 1024;
const SIGNATURE_DOMAIN: &[u8] = b"ExaCopy/owner/v1\0";

/// The BLAKE3 digest of one complete canonical signed owner envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerDigest([u8; 32]);

impl OwnerDigest {
	/// Wraps a recorded digest for comparison with [`OwnerRecord::digest`].
	/// Authenticating the signed owner envelope is a separate verification step.
	#[must_use]
	pub const fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Returns the digest bytes used when binding the initial journal record.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// Immutable signed owner evidence for a local preserve-mode job.
///
/// The signature authenticates declared claims to the selected profile. Recovery
/// must validate live ownership, containment, identities and journal bindings
/// separately before using those claims in its decisions.
#[derive(Eq, PartialEq)]
pub struct OwnerRecord {
	manifest: OwnerManifest,
	verifying_key: VerifyingKey,
	bytes: Vec<u8>,
}

impl OwnerRecord {
	/// Signs the manifest with the supplied local profile signing key.
	///
	/// The caller supplies its own profile key, creation time and independently
	/// generated owner token. The returned bytes require owner-private handling.
	///
	/// # Errors
	/// Returns a typed error for invalid manifest claims or an unsupported signer.
	pub fn sign(manifest: OwnerManifest, profile_key: &SigningKey) -> Result<Self, OwnerError> {
		manifest.validate()?;
		let verifying_key = profile_key.verifying_key();
		if verifying_key.is_weak() {
			return Err(OwnerError::InvalidSignature);
		}
		let public_key = verifying_key.to_bytes();
		let encoded_body = codec::encode_body(&manifest, &public_key)?;
		let body = codec::encoded_bytes(&encoded_body);
		let signature = profile_key
			.try_sign(&signature_input(body))
			.map_err(|_| OwnerError::InvalidSignature)?;
		let envelope = Envelope {
			body,
			public_key,
			signature: signature.to_bytes(),
		};
		let encoded = codec::encode_envelope(&envelope)?;
		Ok(Self {
			manifest,
			verifying_key,
			bytes: codec::encoded_bytes(&encoded).to_vec(),
		})
	}

	/// Decodes and authenticates the entire envelope against an independently selected profile.
	///
	/// The expected profile and verifying key must come from local trust configuration.
	///
	/// # Errors
	/// Rejects oversized, noncanonical, unsupported or unauthenticated evidence.
	pub fn decode(
		bytes: &[u8],
		expected_profile: OwnerProfileId,
		expected_key: &VerifyingKey,
	) -> Result<Self, OwnerError> {
		if bytes.len() > MAX_OWNER_BYTES {
			return Err(OwnerError::Length);
		}
		let envelope = codec::decode_envelope(bytes)?;
		let public_key = expected_key.to_bytes();
		if envelope.public_key != public_key {
			return Err(OwnerError::UntrustedKey);
		}
		let manifest = codec::decode_body(envelope.body, &public_key)?;
		if manifest.profile != expected_profile {
			return Err(OwnerError::UntrustedProfile);
		}
		let signature = Signature::from_bytes(&envelope.signature);
		expected_key
			.verify_strict(&signature_input(envelope.body), &signature)
			.map_err(|_| OwnerError::InvalidSignature)?;
		Ok(Self {
			manifest,
			verifying_key: *expected_key,
			bytes: bytes.to_vec(),
		})
	}

	/// Borrows the authenticated signed claims.
	#[must_use]
	pub const fn manifest(&self) -> &OwnerManifest {
		&self.manifest
	}

	/// Borrows the profile public key that signed the owner claims.
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

impl fmt::Debug for OwnerRecord {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("OwnerRecord")
			.field("manifest", &self.manifest)
			.field("verifying_key", &self.verifying_key)
			.finish_non_exhaustive()
	}
}

fn signature_input(body: &[u8]) -> Vec<u8> {
	[SIGNATURE_DOMAIN, body].concat()
}
