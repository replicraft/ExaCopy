use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::frame::{ChainHead, FRAME_OVERHEAD_BYTES, FrameKind, FrameWriter};
use crate::owner::codec::{self as envelope_codec, Envelope, encoded_bytes};
use crate::{JournalJobId, OwnerDigest, OwnerError, OwnerProfileId, OwnerToken};

use super::codec::{self, DOMAIN, OWNER_BODY_BYTES};
use super::{
	WindowsBootstrapEncodeError, WindowsBootstrapOwnerError, WindowsBootstrapRoles,
	WindowsBootstrapSelection,
};

/// Exact signed Windows bootstrap owner length.
pub const OWNER_BYTES: usize = 342;
/// Exact Windows bootstrap prepared payload length.
pub const PREPARED_BYTES: usize = 218;
/// Exact complete first-segment frame length.
pub const FIRST_SEGMENT_BYTES: usize = PREPARED_BYTES + FRAME_OVERHEAD_BYTES;

/// Claims to encode or claims authenticated by a successful historical inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsBootstrapOwner {
	/// The independently selected profile ID.
	pub profile: OwnerProfileId,
	/// The independently selected job ID.
	pub job: JournalJobId,
	/// An independent owner token.
	pub token: OwnerToken,
	/// The exact identities of the original five layout roles.
	pub roles: WindowsBootstrapRoles,
}

impl WindowsBootstrapOwner {
	pub(super) fn validate(self) -> Result<(), OwnerError> {
		if self.token.as_bytes() == self.job.as_bytes()
			|| self.token.as_bytes() == self.profile.as_bytes()
		{
			return Err(OwnerError::InvalidToken);
		}
		Ok(())
	}
}

/// Bytes for externally provisioned bootstrap storage fixtures.
#[derive(Eq, PartialEq)]
pub struct WindowsBootstrapBytes {
	/// The canonical signed owner envelope.
	pub owner: [u8; OWNER_BYTES],
	/// The canonical prepared frame at byte zero.
	pub first_segment: [u8; FIRST_SEGMENT_BYTES],
}

impl std::fmt::Debug for WindowsBootstrapBytes {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter
			.debug_struct("WindowsBootstrapBytes")
			.finish_non_exhaustive()
	}
}

/// Signs the supplied claims and constructs the two fixed-size byte strings.
///
/// Both record objects and their roles must be provisioned and independently
/// observed before signing. This function has no I/O or publication effects.
///
/// # Errors
/// Refuses invalid claims, a noncanonical or weak key, or a framing failure.
pub fn sign(
	owner: &WindowsBootstrapOwner,
	key: &SigningKey,
) -> Result<WindowsBootstrapBytes, WindowsBootstrapEncodeError> {
	let bytes = sign_owner(owner, key).map_err(WindowsBootstrapEncodeError::Owner)?;
	let payload = codec::encode_prepared(owner, digest(&bytes))
		.map_err(WindowsBootstrapOwnerError::from)
		.map_err(WindowsBootstrapEncodeError::Owner)?;
	let mut first_segment = [0; FIRST_SEGMENT_BYTES];
	FrameWriter::new(&mut first_segment[..], ChainHead::start())
		.append(FrameKind::JobPrepared, &payload)
		.map_err(WindowsBootstrapEncodeError::Frame)?;
	Ok(WindowsBootstrapBytes {
		owner: bytes,
		first_segment,
	})
}

fn sign_owner(
	owner: &WindowsBootstrapOwner,
	key: &SigningKey,
) -> Result<[u8; OWNER_BYTES], WindowsBootstrapOwnerError> {
	owner.validate()?;
	let verifying_key = key.verifying_key();
	require_canonical_strong(&verifying_key)?;
	let public_key = verifying_key.to_bytes();
	let body = codec::encode_owner(owner, &public_key)?;
	let body = encoded_bytes(&body);
	let signature = key
		.try_sign(&DOMAIN.signature_input(body))
		.map_err(|_| OwnerError::InvalidSignature)?;
	let envelope = Envelope {
		body,
		public_key,
		signature: signature.to_bytes(),
	};
	let encoded = envelope_codec::encode_envelope_bounded::<OWNER_BYTES>(&envelope, DOMAIN)?;
	encoded_bytes(&encoded)
		.try_into()
		.map_err(|_| OwnerError::Length.into())
}

pub(super) fn authenticate_owner(
	bytes: &[u8],
	selection: &WindowsBootstrapSelection<'_>,
	observed_roles: WindowsBootstrapRoles,
) -> Result<WindowsBootstrapOwner, WindowsBootstrapOwnerError> {
	if bytes.len() != OWNER_BYTES {
		return Err(OwnerError::Length.into());
	}
	require_canonical_strong(selection.key)?;
	let envelope =
		envelope_codec::decode_envelope_bounded::<OWNER_BODY_BYTES, OWNER_BYTES>(bytes, DOMAIN)?;
	let public_key = selection.key.to_bytes();
	if envelope.public_key != public_key {
		return Err(OwnerError::UntrustedKey.into());
	}
	let signature = Signature::from_bytes(&envelope.signature);
	selection
		.key
		.verify_strict(&DOMAIN.signature_input(envelope.body), &signature)
		.map_err(|_| OwnerError::InvalidSignature)?;
	let owner = codec::decode_owner(envelope.body, &public_key)?;
	if owner.profile != selection.profile {
		return Err(OwnerError::UntrustedProfile.into());
	}
	if owner.job != selection.job {
		return Err(WindowsBootstrapOwnerError::Job);
	}
	if owner.roles.root() != selection.root || observed_roles.root() != selection.root {
		return Err(WindowsBootstrapOwnerError::Root);
	}
	if owner.roles != observed_roles {
		return Err(WindowsBootstrapOwnerError::Roles);
	}
	Ok(owner)
}

pub(super) fn digest(bytes: &[u8]) -> OwnerDigest {
	OwnerDigest::from_bytes(*blake3::hash(bytes).as_bytes())
}

fn require_canonical_strong(key: &VerifyingKey) -> Result<(), OwnerError> {
	if key.is_weak() || key.to_edwards().compress().to_bytes() != key.to_bytes() {
		return Err(OwnerError::InvalidSignature);
	}
	Ok(())
}
