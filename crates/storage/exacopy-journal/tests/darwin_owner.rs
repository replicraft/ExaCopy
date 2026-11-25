//! Managed APFS signed owner codec, including exact profile and trust refusals.

use std::num::{NonZeroU32, NonZeroU64};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use exacopy_journal::{
	DarwinFileIdentity, DarwinOwnerManifest, DarwinOwnerRecord, DarwinVolumeIdentity, JournalJobId,
	LinuxFileIdentity, MAX_OWNER_BYTES, OwnerDigest, OwnerError, OwnerManifest, OwnerProfileId,
	OwnerRecord, OwnerStateDirectory, OwnerTimestamp, OwnerToken, PlanDigest,
};

#[path = "darwin_owner/identity.rs"]
mod identity;

const JOB: [u8; 16] = [
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x7c, 0xde, 0x8f, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
];
const DOMAIN: &[u8] = b"ExaCopy/owner/darwin-managed-apfs/v1\0";
const LINUX_DOMAIN: &[u8] = b"ExaCopy/owner/v1\0";
const DOMAIN_CODE: u8 = 2;
const DARWIN_UID_MAX: u32 = 2_147_483_647;

// Canonical CBOR assembled by hand and signed by Python cryptography
// Ed25519PrivateKey using the fixture seed in signing_key().
const GOLDEN_HEX: &str = concat!(
	"a40058f4ac00a30002010002010150cccccccccccccccccccccccccccccccc0250012345",
	"6789ab7cde8f0123456789abcd035022222222222222222222222222222222045820d04a",
	"b232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873705a2003b7fff",
	"ffffffffffff010006a300020144feffffff02821904d2181a07a400a300020144feffff",
	"ff02821904d2181a0148ffffffffffffffff02f603a2001b7fffffffffffffff011a3b9a",
	"c9ff08582033333333333333333333333333333333333333333333333333333333333333",
	"3309000a83676a6f75726e616c6872656365697074736573746167650b1901f5015820d0",
	"4ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737025840cf29",
	"6ab54330d844a3ae90b7143639c86bf426f8abdbb31cd68ec6247f768a86e4c76a5abc5f",
	"c3157989187d89a947037b13b5fe995f5a78a8b36889e3e871010302",
);
const BODY_START: usize = 4;
const BODY_LEN: usize = 244;
const FORMAT_MAJOR: usize = 4;
const FORMAT_MINOR: usize = 6;
const REQUIRED_FEATURES: usize = 8;
const TOKEN_BYTES: usize = 11;
const BODY_KEY_BYTES: usize = 66;
const VOLUME_PLATFORM: usize = 115;
const VOLUME_DEVICE_BYTES: usize = 118;
const VOLUME_FSID: usize = 123;
const ROOT_PLATFORM: usize = 134;
const ROOT_DEVICE_BYTES: usize = 137;
const ROOT_INODE_BYTES: usize = 150;
const ROOT_GENERATION: usize = 159;
const BIRTH_NANOS: usize = 173;
const POLICY: usize = 214;
const DIRECTORIES: usize = 216;
const RECEIPTS_NAME: usize = 226;
const UID: usize = 241;
const ENVELOPE_KEY_BYTES: usize = BODY_START + BODY_LEN + 3;
const SIGNATURE_BYTES: usize = ENVELOPE_KEY_BYTES + 32 + 3;

#[test]
fn independent_golden_and_repeated_signatures_agree() {
	let key = signing_key();
	let signed = DarwinOwnerRecord::sign(manifest(), &key).expect("valid owner manifest");
	assert_eq!(signed, DarwinOwnerRecord::sign(manifest(), &key).unwrap());
	assert_eq!(signed.as_bytes(), golden());
	assert_eq!(
		signed.digest(),
		OwnerDigest::from_bytes(*blake3::hash(&golden()).as_bytes())
	);
	assert_eq!(decode(&golden()), Ok(signed));
	assert_eq!(decode(&golden()).unwrap().manifest(), &manifest());
	assert_eq!(
		decode(&golden()).unwrap().verifying_key(),
		&key.verifying_key()
	);
}

#[test]
fn cross_profile_envelopes_and_mixed_discriminants_are_refused() {
	let darwin = golden();
	let manifest = manifest();
	let key = signing_key();
	let linux = OwnerRecord::sign(
		OwnerManifest {
			token: manifest.token,
			job: manifest.job,
			profile: manifest.profile,
			created: manifest.created,
			destination_device: 7,
			state_root: LinuxFileIdentity::new(7, 9),
			plan_digest: manifest.plan_digest,
			directories: vec![OwnerStateDirectory::Journal],
		},
		&key,
	)
	.unwrap();

	assert_eq!(decode(linux.as_bytes()), Err(OwnerError::WrongDomain));
	assert_eq!(
		OwnerRecord::decode(&darwin, profile(), &key.verifying_key()),
		Err(OwnerError::WrongDomain)
	);
	let linux_len = usize::from(linux.as_bytes()[3]);
	let linux_body = &linux.as_bytes()[BODY_START..BODY_START + linux_len];
	assert_eq!(
		decode(&resign(linux_body, DOMAIN, DOMAIN_CODE)),
		Err(OwnerError::InvalidCbor)
	);
	assert_eq!(
		OwnerRecord::decode(
			&resign(&body(), LINUX_DOMAIN, 1),
			profile(),
			&key.verifying_key()
		),
		Err(OwnerError::InvalidCbor)
	);
	assert_eq!(
		decode(&resign(&body(), LINUX_DOMAIN, DOMAIN_CODE)),
		Err(OwnerError::InvalidSignature)
	);
}

#[test]
fn authentication_uses_the_external_key_and_profile() {
	let foreign = SigningKey::from_bytes(&[0x12; 32]);
	let mut bytes = golden();
	bytes[SIGNATURE_BYTES] ^= 1;
	assert_eq!(decode(&bytes), Err(OwnerError::InvalidSignature));
	let mut bytes = golden();
	bytes[BODY_START + TOKEN_BYTES] ^= 1;
	assert_eq!(decode(&bytes), Err(OwnerError::InvalidSignature));

	let mut wrong_envelope_key = golden();
	wrong_envelope_key[ENVELOPE_KEY_BYTES..ENVELOPE_KEY_BYTES + 32]
		.copy_from_slice(foreign.verifying_key().as_bytes());
	assert_eq!(decode(&wrong_envelope_key), Err(OwnerError::UntrustedKey));

	let foreign_record = DarwinOwnerRecord::sign(manifest(), &foreign).unwrap();
	assert_eq!(
		decode(foreign_record.as_bytes()),
		Err(OwnerError::UntrustedKey)
	);
	let mut forged_body = body();
	forged_body[BODY_KEY_BYTES..BODY_KEY_BYTES + 32]
		.copy_from_slice(foreign.verifying_key().as_bytes());
	assert_eq!(
		decode(&signed_body(&forged_body)),
		Err(OwnerError::UntrustedKey)
	);
	assert_eq!(
		DarwinOwnerRecord::decode(
			&golden(),
			OwnerProfileId::from_bytes([0x13; 16]).unwrap(),
			&signing_key().verifying_key()
		),
		Err(OwnerError::UntrustedProfile)
	);
	let mut identity = [0; 32];
	identity[0] = 1;
	let weak = VerifyingKey::from_bytes(&identity).unwrap();
	let mut signature = [0; 64];
	signature[0] = 1;
	let mut weak_body = body();
	weak_body[BODY_KEY_BYTES..BODY_KEY_BYTES + 32].copy_from_slice(&identity);
	assert_eq!(
		DarwinOwnerRecord::decode(
			&envelope(&weak_body, identity, signature, DOMAIN_CODE),
			profile(),
			&weak,
		),
		Err(OwnerError::InvalidSignature)
	);
}

#[test]
fn signed_unsupported_values_and_identity_mismatches_are_refused() {
	for (index, input_len, replacement, error) in [
		(FORMAT_MAJOR, 1, &[1][..], OwnerError::UnsupportedVersion),
		(FORMAT_MINOR, 1, &[1][..], OwnerError::UnsupportedVersion),
		(
			REQUIRED_FEATURES,
			1,
			&[0][..],
			OwnerError::UnsupportedVersion,
		),
		(
			REQUIRED_FEATURES,
			1,
			&[3][..],
			OwnerError::UnsupportedVersion,
		),
		(
			VOLUME_PLATFORM,
			1,
			&[1][..],
			OwnerError::UnsupportedIdentity,
		),
		(ROOT_PLATFORM, 1, &[1][..], OwnerError::UnsupportedIdentity),
		(
			VOLUME_DEVICE_BYTES,
			4,
			&[0; 4][..],
			OwnerError::UnsupportedIdentity,
		),
		(
			VOLUME_DEVICE_BYTES - 1,
			5,
			&[0x48, 0, 0, 0, 0, 1, 0, 0, 0][..],
			OwnerError::Length,
		),
		(
			VOLUME_FSID,
			6,
			&[0x82, 0, 0][..],
			OwnerError::UnsupportedIdentity,
		),
		(
			VOLUME_FSID,
			6,
			&[0x82, 1, 0][..],
			OwnerError::DarwinVolumeMismatch,
		),
		(
			VOLUME_FSID,
			6,
			&[0x81, 1][..],
			OwnerError::UnsupportedIdentity,
		),
		(
			ROOT_DEVICE_BYTES,
			1,
			&[0xfd][..],
			OwnerError::DarwinVolumeMismatch,
		),
		(
			ROOT_INODE_BYTES,
			8,
			&[0; 8][..],
			OwnerError::UnsupportedIdentity,
		),
		(
			ROOT_GENERATION,
			1,
			&[0][..],
			OwnerError::UnsupportedIdentity,
		),
		(
			ROOT_GENERATION,
			1,
			&[0xf7][..],
			OwnerError::UnsupportedIdentity,
		),
		(
			ROOT_GENERATION,
			1,
			&[0x1b, 0, 0, 0, 1, 0, 0, 0, 0][..],
			OwnerError::UnsupportedIdentity,
		),
		(
			BIRTH_NANOS,
			5,
			&[0x1a, 0x3b, 0x9a, 0xca, 0][..],
			OwnerError::InvalidTimestamp,
		),
		(POLICY, 1, &[1][..], OwnerError::UnsupportedPolicy),
		(DIRECTORIES, 1, &[0x82][..], OwnerError::InvalidDirectories),
		(
			RECEIPTS_NAME,
			8,
			b"versions",
			OwnerError::InvalidDirectories,
		),
		(UID - 1, 1, &[10][..], OwnerError::InvalidCbor),
	] {
		let mut unsupported = body();
		unsupported.splice(index..index + input_len, replacement.iter().copied());
		assert_eq!(
			decode(&signed_body(&unsupported)),
			Err(error),
			"body byte {index}"
		);
	}
}

#[test]
fn canonical_and_size_boundaries_are_enforced() {
	let bytes = golden();
	for cut in 0..bytes.len() {
		assert!(decode(&bytes[..cut]).is_err(), "truncation at {cut}");
	}
	let mut suffixed = bytes.clone();
	suffixed.push(0);
	assert_eq!(decode(&suffixed), Err(OwnerError::TrailingBytes));
	let mut aliased_envelope = bytes.clone();
	aliased_envelope.splice(2..3, [0x59, 0]);
	assert_eq!(decode(&aliased_envelope), Err(OwnerError::NonCanonical));
	let mut indefinite = bytes;
	indefinite[0] = 0xbf;
	indefinite.push(0xff);
	assert_eq!(decode(&indefinite), Err(OwnerError::InvalidCbor));
	let mut suffixed = body();
	suffixed.push(0);
	assert_eq!(
		decode(&signed_body(&suffixed)),
		Err(OwnerError::TrailingBytes)
	);
	for (index, value) in [(FORMAT_MAJOR, 2), (ROOT_GENERATION, 0), (POLICY, 0)] {
		let mut aliased = body();
		aliased.splice(index..=index, [0x18, value]);
		let error = if index == ROOT_GENERATION {
			OwnerError::UnsupportedIdentity
		} else {
			OwnerError::NonCanonical
		};
		assert_eq!(decode(&signed_body(&aliased)), Err(error));
	}
	let overlong = [0xa4, 0, 0x59, 0x02, 0x01]
		.into_iter()
		.chain([0; 513])
		.collect::<Vec<_>>();
	assert_eq!(decode(&overlong), Err(OwnerError::Length));
	assert_eq!(
		decode(&vec![0; MAX_OWNER_BYTES + 1]),
		Err(OwnerError::Length)
	);
}

#[test]
fn signed_inner_body_prefixes_are_refused() {
	let body = body();
	for cut in 0..body.len() {
		assert_eq!(
			decode(&signed_body(&body[..cut])),
			Err(OwnerError::InvalidCbor),
			"framed inner body cut at {cut}"
		);
	}
}

#[test]
fn positive_generation_must_use_minimal_encoding() {
	let mut canonical = body();
	canonical[ROOT_GENERATION] = 1;
	let record = decode(&signed_body(&canonical)).expect("canonical generation evidence");
	assert_eq!(
		record.manifest().state_root.generation(),
		NonZeroU32::new(1)
	);

	let mut aliased = canonical;
	aliased.splice(ROOT_GENERATION..=ROOT_GENERATION, [0x18, 1]);
	assert_eq!(
		decode(&signed_body(&aliased)),
		Err(OwnerError::NonCanonical)
	);
}

#[test]
fn max_native_widths_and_available_generation_fit() {
	let mut manifest = manifest();
	let mut volume = DarwinVolumeIdentity::new(i32::MIN, [u32::MAX, u32::MAX]).unwrap();
	assert_eq!(volume.device(), i32::MIN);
	assert_eq!(volume.physical_fsid(), [u32::MAX, u32::MAX]);
	for seconds in [i64::MIN, i64::MAX] {
		let timestamp = OwnerTimestamp::new(seconds, 999_999_999).unwrap();
		manifest.created = timestamp;
		manifest.destination_volume = volume;
		manifest.state_root =
			DarwinFileIdentity::new(volume, NonZeroU64::MAX, Some(NonZeroU32::MAX), timestamp);
		manifest.state_root_uid = NonZeroU32::new(DARWIN_UID_MAX).unwrap();
		let record = DarwinOwnerRecord::sign(manifest.clone(), &signing_key()).unwrap();
		assert_eq!(decode(record.as_bytes()), Ok(record));
		volume = DarwinVolumeIdentity::new(i32::MAX, [u32::MAX, u32::MAX]).unwrap();
	}
}

#[test]
fn signing_refuses_mismatched_volume_and_token_aliases() {
	let mut claims = manifest();
	claims.destination_volume = DarwinVolumeIdentity::new(-2, [1234, 0]).unwrap();
	assert_eq!(
		DarwinOwnerRecord::sign(claims, &signing_key()),
		Err(OwnerError::DarwinVolumeMismatch)
	);
	for related in [JOB, *profile().as_bytes()] {
		let mut claims = manifest();
		claims.token = OwnerToken::from_bytes(related).unwrap();
		assert_eq!(
			DarwinOwnerRecord::sign(claims, &signing_key()),
			Err(OwnerError::InvalidToken)
		);
	}
	let record = decode(&golden()).unwrap();
	let debug = format!("{record:?}");
	assert!(debug.contains("OwnerToken(<redacted>)"));
	assert!(!debug.contains("204, 204"));
	assert!(!debug.contains("bytes:"));
}

fn manifest() -> DarwinOwnerManifest {
	let volume = DarwinVolumeIdentity::new(-2, [1234, 26]).unwrap();
	DarwinOwnerManifest {
		token: OwnerToken::from_bytes([0xcc; 16]).unwrap(),
		job: JournalJobId::from_bytes(JOB).unwrap(),
		profile: profile(),
		created: OwnerTimestamp::new(i64::MIN, 0).unwrap(),
		destination_volume: volume,
		state_root: DarwinFileIdentity::new(
			volume,
			NonZeroU64::MAX,
			None,
			OwnerTimestamp::new(i64::MAX, 999_999_999).unwrap(),
		),
		state_root_uid: NonZeroU32::new(501).unwrap(),
		plan_digest: PlanDigest::from_bytes([0x33; 32]),
	}
}

fn signing_key() -> SigningKey {
	SigningKey::from_bytes(&[0x11; 32])
}

fn profile() -> OwnerProfileId {
	OwnerProfileId::from_bytes([0x22; 16]).unwrap()
}

fn golden() -> Vec<u8> {
	let (pairs, remainder) = GOLDEN_HEX.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty());
	pairs
		.iter()
		.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
		.collect()
}

fn body() -> Vec<u8> {
	golden()[BODY_START..BODY_START + BODY_LEN].to_vec()
}

fn decode(bytes: &[u8]) -> Result<DarwinOwnerRecord, OwnerError> {
	DarwinOwnerRecord::decode(bytes, profile(), &signing_key().verifying_key())
}

fn signed_body(body: &[u8]) -> Vec<u8> {
	resign(body, DOMAIN, DOMAIN_CODE)
}

fn resign(body: &[u8], domain: &[u8], code: u8) -> Vec<u8> {
	let key = signing_key();
	let signature = key.sign(&[domain, body].concat());
	envelope(
		body,
		key.verifying_key().to_bytes(),
		signature.to_bytes(),
		code,
	)
}

fn envelope(body: &[u8], key: [u8; 32], signature: [u8; 64], code: u8) -> Vec<u8> {
	let length = u8::try_from(body.len()).expect("fixture uses one-byte length");
	let mut header = vec![0xa4, 0];
	if length >= 24 {
		header.extend([0x58, length]);
	} else {
		header.push(0x40 | length);
	}
	[
		&header,
		body,
		&[1, 0x58, 0x20],
		&key,
		&[2, 0x58, 0x40],
		&signature,
		&[3, code],
	]
	.concat()
}
