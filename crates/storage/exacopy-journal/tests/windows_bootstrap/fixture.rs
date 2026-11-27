use std::io::{self, Read};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use exacopy_journal::windows_bootstrap::{
	WindowsBootstrapFileIdentity as Identity, WindowsBootstrapOwner,
	WindowsBootstrapRoles as Roles, WindowsBootstrapSelection,
};
use exacopy_journal::{JournalJobId, OwnerProfileId, OwnerToken};

pub const GUID: [u8; 36] = *b"01234567-89ab-cdef-8012-3456789abcde";
pub const SERIAL: u64 = 0x89ab_cdef_0123_4567;
pub const JOB: [u8; 16] = [
	0x01, 0x8d, 0x45, 0xbe, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1,
];
pub const PROFILE: [u8; 16] = [0x11; 16];
pub const TOKEN: [u8; 16] = [0x22; 16];
pub const DOMAIN: &[u8] = b"ExaCopy/owner/windows-fixed-ntfs-bootstrap/v1\0";
pub const OWNER_BODY: std::ops::Range<usize> = 4..238;
pub const HEADER_BYTES: usize = 56;
pub const FRAME_PAYLOAD_END: usize = HEADER_BYTES + 218;
pub const BODY_PROFILE_START: usize = 11;
pub const BODY_TOKEN_START: usize = 47;
pub const BODY_KEY_START: usize = 66;
pub const BODY_LAYOUT: usize = 99;
pub const BODY_ROLES: usize = 101;
pub const ROLE_GUID: usize = 3;
pub const ROLE_ID: usize = 49;
pub const ROLE_ID_STRIDE: usize = 17;

pub fn signing_key() -> SigningKey {
	SigningKey::from_bytes(&[0x31; 32])
}

fn id(index: u8) -> [u8; 16] {
	[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, index]
}

pub fn identity(guid: [u8; 36], serial: u64, index: u8) -> Identity {
	Identity::new(guid, serial, id(index)).unwrap()
}

pub fn role_tuple([root, job, owner, journal, segment]: [Identity; 5]) -> Roles {
	Roles::new(root, job, owner, journal, segment).unwrap()
}

pub fn observed(serial: u64) -> [Identity; 5] {
	[1, 2, 3, 4, 5].map(|index| identity(GUID, serial, index))
}

pub fn owner(serial: u64) -> WindowsBootstrapOwner {
	WindowsBootstrapOwner {
		profile: OwnerProfileId::from_bytes(PROFILE).unwrap(),
		job: JournalJobId::from_bytes(JOB).unwrap(),
		token: OwnerToken::from_bytes(TOKEN).unwrap(),
		roles: role_tuple(observed(serial)),
	}
}

pub fn selection(
	key: &VerifyingKey,
	owner: WindowsBootstrapOwner,
) -> WindowsBootstrapSelection<'_> {
	WindowsBootstrapSelection {
		profile: owner.profile,
		job: owner.job,
		key,
		root: owner.roles.root(),
	}
}

// The literal B1 field oracle comes from the adopted vector, independently
// of the journal owner codec, minicbor or the existing frame writer.
fn roles(serial: u64) -> Vec<u8> {
	let serial_bytes = match serial {
		SERIAL => [0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89],
		0 => [0; 8],
		_ => panic!("serial outside the independent specimen"),
	};
	let mut bytes = vec![0x87, 0x58, 0x24];
	bytes.extend(GUID);
	bytes.push(0x48);
	bytes.extend(serial_bytes);
	for index in 1..=5 {
		bytes.push(0x50);
		bytes.extend(id(index));
	}
	assert_eq!(bytes.len(), 133);
	bytes
}

pub fn owner_body(serial: u64, key: &VerifyingKey) -> Vec<u8> {
	let mut bytes = vec![0xa7, 0, 0xa3, 0, 1, 1, 0, 2, 1, 1, 0x50];
	bytes.extend(PROFILE);
	bytes.extend([2, 0x50]);
	bytes.extend(JOB);
	bytes.extend([3, 0x50]);
	bytes.extend(TOKEN);
	bytes.extend([4, 0x58, 0x20]);
	bytes.extend(key.to_bytes());
	bytes.extend([5, 1, 6]);
	bytes.extend(roles(serial));
	assert_eq!(bytes.len(), 234);
	bytes
}

pub fn signed(body: &[u8], signer: &SigningKey, domain: &[u8], code: u8) -> Vec<u8> {
	let signature = signer.try_sign(&[domain, body].concat()).unwrap();
	let mut bytes = vec![0xa4, 0, 0x58, u8::try_from(body.len()).unwrap()];
	bytes.extend(body);
	bytes.extend([1, 0x58, 0x20]);
	bytes.extend(signer.verifying_key().to_bytes());
	bytes.extend([2, 0x58, 0x40]);
	bytes.extend(signature.to_bytes());
	bytes.extend([3, code]);
	bytes
}

pub fn prepared(serial: u64, signed_owner: &[u8]) -> Vec<u8> {
	let mut bytes = vec![0xa7, 0, 0xa3, 0, 1, 1, 0, 2, 1, 1, 5, 2, 0x50];
	bytes.extend(JOB);
	bytes.extend([3, 0x50]);
	bytes.extend(TOKEN);
	bytes.extend([4, 0x58, 0x20]);
	bytes.extend(blake3::hash(signed_owner).as_bytes());
	bytes.extend([5, 1, 6]);
	bytes.extend(roles(serial));
	assert_eq!(bytes.len(), 218);
	bytes
}

pub fn frame(payload: &[u8], kind: u16, sequence: u64, previous: [u8; 32]) -> Vec<u8> {
	let mut bytes = b"EXAJNL01\x01\0".to_vec();
	bytes.extend(kind.to_le_bytes());
	bytes.extend(u32::try_from(payload.len()).unwrap().to_le_bytes());
	bytes.extend(sequence.to_le_bytes());
	bytes.extend(previous);
	assert_eq!(bytes.len(), HEADER_BYTES);
	bytes.extend(payload);

	// Bitwise reflected CRC32C and independently selected BLAKE3 inputs.
	let mut crc = !0_u32;
	for &byte in &bytes {
		crc ^= u32::from(byte);
		for _ in 0..8 {
			let poly = if crc & 1 == 0 { 0 } else { 0x82f6_3b78 };
			crc = (crc >> 1) ^ poly;
		}
	}
	bytes.extend((!crc).to_le_bytes());
	let mut hash = blake3::Hasher::new();
	hash.update(b"ExaCopy/journal-record/v1\0");
	hash.update(&bytes);
	bytes.extend(hash.finalize().as_bytes());
	bytes
}

pub struct EndError<'a>(pub &'a [u8]);

impl Read for EndError<'_> {
	fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
		if self.0.is_empty() {
			return Err(io::Error::other("failed terminal observation"));
		}
		self.0.read(bytes)
	}
}
