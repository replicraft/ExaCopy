//! Canonical signed acknowledgments for explicit managed synchronization Init.

use std::num::NonZeroU64;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use exacopy_endpoint::UnixComponent;
use exacopy_platform::linux::FileIdentity;

use crate::profile::profile_id_for_key;

use super::managed_policy::{ManagedPolicyIdentity, ManagedPolicyPin};

#[cfg(test)]
mod tests;

const VERSION: u8 = 1;
const PAYLOAD_BYTES: usize = 153;
const SIGNATURE_BYTES: usize = 64;
const SIGNATURE_DOMAIN: &[u8] = b"ExaCopy local managed sync Init ack v1\0";
const PATH_DOMAIN: &str = "ExaCopy local managed sync Init profile path v1";
const SIGNING_BYTES: usize = SIGNATURE_DOMAIN.len() + PAYLOAD_BYTES;
const MAX_PATH_BYTES: usize = 4095;
const MIN_PATH_COMPONENTS: usize = 2;
const MAX_PATH_COMPONENTS: usize = 64;
const HEX: &[u8; 16] = b"0123456789abcdef";

pub(crate) const MANAGED_ACK_BYTES: usize = 2 * (PAYLOAD_BYTES + SIGNATURE_BYTES) + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManagedAckError {
	Encoding,
	Path,
	Owner,
	Selection,
	Signature,
}

/// Verified signed expectations. Native path custody still needs to be admitted.
#[derive(Debug)]
pub(crate) struct VerifiedManagedAck {
	pin: ManagedPolicyPin,
	device: u64,
	inode: NonZeroU64,
}

impl VerifiedManagedAck {
	pub(crate) const fn pin(&self) -> ManagedPolicyPin {
		self.pin
	}

	pub(crate) const fn device(&self) -> u64 {
		self.device
	}

	pub(crate) const fn inode(&self) -> NonZeroU64 {
		self.inode
	}
}

pub(crate) fn profile_path_digest(path: &Path) -> Result<[u8; 32], ManagedAckError> {
	let bytes = path.as_os_str().as_bytes();
	let relative = bytes.strip_prefix(b"/").ok_or(ManagedAckError::Path)?;
	if bytes.len() > MAX_PATH_BYTES {
		return Err(ManagedAckError::Path);
	}
	let mut components = 0;
	for component in relative.split(|&byte| byte == b'/') {
		UnixComponent::new(component).map_err(|_| ManagedAckError::Path)?;
		components += 1;
	}
	if !(MIN_PATH_COMPONENTS..=MAX_PATH_COMPONENTS).contains(&components) {
		return Err(ManagedAckError::Path);
	}
	Ok(blake3::derive_key(PATH_DOMAIN, bytes))
}

/// Encodes an acknowledgment with the signer already held by the Init path.
pub(crate) fn sign(
	pin: &ManagedPolicyPin,
	profile: FileIdentity,
	path_digest: [u8; 32],
	signer: &SigningKey,
) -> Result<[u8; MANAGED_ACK_BYTES], ManagedAckError> {
	let inode = NonZeroU64::new(profile.inode()).ok_or(ManagedAckError::Selection)?;
	sign_identity(pin, profile.device(), inode, path_digest, signer)
}

fn sign_identity(
	pin: &ManagedPolicyPin,
	device: u64,
	inode: NonZeroU64,
	path_digest: [u8; 32],
	signer: &SigningKey,
) -> Result<[u8; MANAGED_ACK_BYTES], ManagedAckError> {
	check_owner(&signer.verifying_key(), &pin.identity)?;
	if pin.identity.selection_id == [0; 16] {
		return Err(ManagedAckError::Selection);
	}
	let payload = payload(pin, device, inode, path_digest);
	let signature = signer.sign(&signing_input(&payload)).to_bytes();
	Ok(encode(&payload, &signature))
}

pub(crate) fn verify(
	bytes: &[u8],
	owner: &VerifyingKey,
	expected_path_digest: [u8; 32],
	expected_selection: [u8; 16],
) -> Result<VerifiedManagedAck, ManagedAckError> {
	let mut raw = [0; PAYLOAD_BYTES + SIGNATURE_BYTES];
	let (newline, digits) = bytes.split_last().ok_or(ManagedAckError::Encoding)?;
	if *newline != b'\n' || digits.len() != MANAGED_ACK_BYTES - 1 {
		return Err(ManagedAckError::Encoding);
	}
	let (pairs, _) = digits.as_chunks::<2>();
	for (out, &[high, low]) in raw.iter_mut().zip(pairs) {
		*out = (digit(high)? << 4) | digit(low)?;
	}
	let (payload, signature) = raw.split_at(PAYLOAD_BYTES);
	let payload: &[u8; PAYLOAD_BYTES] =
		payload.try_into().map_err(|_| ManagedAckError::Encoding)?;
	if payload[0] != VERSION {
		return Err(ManagedAckError::Encoding);
	}
	let selection_id = field(payload, 1);
	let revision = nonzero_field(payload, 17)?;
	let identity = ManagedPolicyIdentity {
		selection_id,
		revision,
		owner_profile: field(payload, 25),
		owner_key: field(payload, 41),
	};
	let device = u64::from_be_bytes(field(payload, 73));
	let inode = nonzero_field(payload, 81)?;
	let path_digest = field::<32>(payload, 89);
	let digest = field(payload, 121);
	if selection_id == [0; 16] || selection_id != expected_selection {
		return Err(ManagedAckError::Selection);
	}
	if path_digest != expected_path_digest {
		return Err(ManagedAckError::Path);
	}
	check_owner(owner, &identity)?;
	let signature = Signature::from_slice(signature).map_err(|_| ManagedAckError::Encoding)?;
	owner
		.verify_strict(&signing_input(payload), &signature)
		.map_err(|_| ManagedAckError::Signature)?;
	Ok(VerifiedManagedAck {
		pin: ManagedPolicyPin { identity, digest },
		device,
		inode,
	})
}

fn check_owner(
	owner: &VerifyingKey,
	identity: &ManagedPolicyIdentity,
) -> Result<(), ManagedAckError> {
	if owner.is_weak()
		|| owner.to_bytes() != identity.owner_key
		|| owner.to_edwards().compress().to_bytes() != identity.owner_key
		|| profile_id_for_key(owner)
			.map_err(|_| ManagedAckError::Owner)?
			.as_bytes()
			!= &identity.owner_profile
	{
		return Err(ManagedAckError::Owner);
	}
	Ok(())
}

fn payload(
	pin: &ManagedPolicyPin,
	device: u64,
	inode: NonZeroU64,
	path_digest: [u8; 32],
) -> [u8; PAYLOAD_BYTES] {
	let mut payload = [0; PAYLOAD_BYTES];
	payload[0] = VERSION;
	payload[1..17].copy_from_slice(&pin.identity.selection_id);
	payload[17..25].copy_from_slice(&pin.identity.revision.get().to_be_bytes());
	payload[25..41].copy_from_slice(&pin.identity.owner_profile);
	payload[41..73].copy_from_slice(&pin.identity.owner_key);
	payload[73..81].copy_from_slice(&device.to_be_bytes());
	payload[81..89].copy_from_slice(&inode.get().to_be_bytes());
	payload[89..121].copy_from_slice(&path_digest);
	payload[121..].copy_from_slice(&pin.digest);
	payload
}

fn signing_input(payload: &[u8; PAYLOAD_BYTES]) -> [u8; SIGNING_BYTES] {
	let mut message = [0; SIGNING_BYTES];
	let (domain, body) = message.split_at_mut(SIGNATURE_DOMAIN.len());
	domain.copy_from_slice(SIGNATURE_DOMAIN);
	body.copy_from_slice(payload);
	message
}

fn field<const N: usize>(payload: &[u8; PAYLOAD_BYTES], offset: usize) -> [u8; N] {
	let mut field = [0; N];
	field.copy_from_slice(&payload[offset..offset + N]);
	field
}

fn nonzero_field(
	payload: &[u8; PAYLOAD_BYTES],
	offset: usize,
) -> Result<NonZeroU64, ManagedAckError> {
	NonZeroU64::new(u64::from_be_bytes(field(payload, offset))).ok_or(ManagedAckError::Selection)
}

fn encode(
	payload: &[u8; PAYLOAD_BYTES],
	signature: &[u8; SIGNATURE_BYTES],
) -> [u8; MANAGED_ACK_BYTES] {
	let mut result = [b'\n'; MANAGED_ACK_BYTES];
	for (index, &byte) in payload.iter().chain(signature).enumerate() {
		result[index * 2] = HEX[usize::from(byte >> 4)];
		result[index * 2 + 1] = HEX[usize::from(byte & 0xf)];
	}
	result
}

fn digit(byte: u8) -> Result<u8, ManagedAckError> {
	match byte {
		b'0'..=b'9' => Ok(byte - b'0'),
		b'a'..=b'f' => Ok(byte - b'a' + 10),
		_ => Err(ManagedAckError::Encoding),
	}
}
