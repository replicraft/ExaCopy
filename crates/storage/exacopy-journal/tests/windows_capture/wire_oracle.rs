//! Independent literal-width fixtures for the selected Windows capture wire profile.

use ed25519_dalek::{Signer, SigningKey};

pub(super) const PREPARED_KIND: u16 = 43;
pub(super) const RANGE_KIND: u16 = 44;
pub(super) const PREPARED_DOMAIN: &[u8] = b"ExaCopy/windows-ntfs-capture/prepared/v1\0";
pub(super) const RANGE_DOMAIN: &[u8] = b"ExaCopy/windows-ntfs-capture/range/v1\0";

pub(super) const PREPARED_FIXED_BYTES: usize = 204;
pub(super) const MAX_TARGET_UNITS: usize = 255;
pub(super) const MAX_PREPARED_PAYLOAD: usize = 778;
pub(super) const RANGE_BODY_BYTES: usize = 116;
pub(super) const RANGE_PAYLOAD_BYTES: usize = 180;
pub(super) const MAX_RANGES: u16 = 4096;
pub(super) const MAX_SEGMENT_BYTES: usize = 1_114_982;

pub(super) const SINGLE_TARGET: [u16; 1] = [0x4e2d];
pub(super) const RAW_TARGET: [u16; 4] = [0x0078, 0xd800, 0x00e9, 0x007a];

// Header and payload offset zero are deliberately separate in these fixtures.
pub(super) const MAX_PREPARED_HEADER_PREFIX: [u8; 24] = [
	0x45, 0x58, 0x41, 0x4a, 0x4e, 0x4c, 0x30, 0x31, 1, 0, 43, 0, 0x0a, 3, 0, 0, 1, 0, 0, 0, 0, 0,
	0, 0,
];
pub(super) const FIRST_RANGE_HEADER_PREFIX: [u8; 24] = [
	0x45, 0x58, 0x41, 0x4a, 0x4e, 0x4c, 0x30, 0x31, 1, 0, 44, 0, 0xb4, 0, 0, 0, 2, 0, 0, 0, 0, 0,
	0, 0,
];
pub(super) const FINAL_RANGE_HEADER_PREFIX: [u8; 24] = [
	0x45, 0x58, 0x41, 0x4a, 0x4e, 0x4c, 0x30, 0x31, 1, 0, 44, 0, 0xb4, 0, 0, 0, 1, 0x10, 0, 0, 0,
	0, 0, 0,
];

pub(super) struct PreparedFields {
	pub(super) owner_digest: [u8; 32],
	pub(super) bootstrap_head_digest: [u8; 32],
	pub(super) sibling_id: [u8; 16],
	pub(super) stage_directory_id: [u8; 16],
	pub(super) stage_payload_id: [u8; 16],
	pub(super) source_scope: [u8; 32],
	pub(super) grant_commitment: [u8; 32],
	pub(super) generation: u64,
	pub(super) epoch: u64,
	pub(super) extent: u64,
}

impl PreparedFields {
	pub(super) fn body(&self, target: &[u16]) -> Vec<u8> {
		assert!((1..=MAX_TARGET_UNITS).contains(&target.len()));
		let mut body = vec![0; PREPARED_FIXED_BYTES + 2 * target.len()];
		body[..2].copy_from_slice(&[1, 0]);
		body[2..34].copy_from_slice(&self.owner_digest);
		body[34..66].copy_from_slice(&self.bootstrap_head_digest);
		body[66..82].copy_from_slice(&self.sibling_id);
		body[82..98].copy_from_slice(&self.stage_directory_id);
		body[98..114].copy_from_slice(&self.stage_payload_id);
		body[114..146].copy_from_slice(&self.source_scope);
		body[146..178].copy_from_slice(&self.grant_commitment);
		body[178..186].copy_from_slice(&self.generation.to_le_bytes());
		body[186..194].copy_from_slice(&self.epoch.to_le_bytes());
		body[194..202].copy_from_slice(&self.extent.to_le_bytes());
		body[202..204].copy_from_slice(&u16::try_from(target.len()).unwrap().to_le_bytes());
		let (units, remainder) = body[204..].as_chunks_mut::<2>();
		assert!(remainder.is_empty());
		for (position, unit) in units.iter_mut().zip(target) {
			position.copy_from_slice(&unit.to_le_bytes());
		}
		body
	}
}

pub(super) fn range_body(
	prepared: [u8; 32],
	previous: [u8; 32],
	ordinal: u16,
	offset: u64,
	length: u64,
	digest: [u8; 32],
) -> [u8; RANGE_BODY_BYTES] {
	let mut body = [0; RANGE_BODY_BYTES];
	body[..2].copy_from_slice(&[1, 0]);
	body[2..34].copy_from_slice(&prepared);
	body[34..66].copy_from_slice(&previous);
	body[66..68].copy_from_slice(&ordinal.to_le_bytes());
	body[68..76].copy_from_slice(&offset.to_le_bytes());
	body[76..84].copy_from_slice(&length.to_le_bytes());
	body[84..116].copy_from_slice(&digest);
	body
}

// The supplied key is a test-only fixed seed. The production codec does not
// participate in either the body construction or the signed message.
pub(super) fn signed_payload(body: &[u8], domain: &[u8], signer: &SigningKey) -> Vec<u8> {
	let signature = signer.try_sign(&[domain, body].concat()).unwrap();
	[body, signature.to_bytes().as_slice()].concat()
}
