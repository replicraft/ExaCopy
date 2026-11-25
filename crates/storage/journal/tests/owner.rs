//! Signed owner-manifest codec and profile-trust boundary tests.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use exacopy_journal::{
	JournalJobId, LinuxFileIdentity, MAX_OWNER_BYTES, OwnerDigest, OwnerError, OwnerManifest,
	OwnerProfileId, OwnerRecord, OwnerStateDirectory, OwnerTimestamp, OwnerToken, PlanDigest,
};

const PROFILE: [u8; 16] = [0x22; 16];
const TOKEN: [u8; 16] = [0xcc; 16];
const JOB: [u8; 16] = [
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x7c, 0xde, 0x8f, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
];
const DOMAIN: &[u8] = b"ExaCopy/owner/v1\0";

// Assembled with literal canonical CBOR headers and signed independently by
// Python cryptography's Ed25519PrivateKey using the seed in signing_key().
const GOLDEN_HEX: &str = concat!(
	"a40058d5ab00a30001010002000150cccccccccccccccccccccccccccccccc0250012345",
	"6789ab7cde8f0123456789abcd035022222222222222222222222222222222045820d04a",
	"b232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873705a20020011a",
	"3b9ac9ff06a200010148070000000000000007a400010148070000000000000002480900",
	"00000000000003f608582033333333333333333333333333333333333333333333333333",
	"3333333333333309000a836b636865636b706f696e7473676a6f75726e616c6573746167",
	"65015820d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
	"025840c43f761079c5ca984b17dfa85959aaf84f436d5c8a74b41ba34f088e80e69671cc",
	"46583927f0018ede82eb2b6af2f4d684ac1530dab00a95c797e372797c66050301",
);

// Offsets into the independently assembled body, relative to its map header.
const BODY_START: usize = 4;
const BODY_LEN: usize = 213;
const FORMAT_MAJOR_BYTE: usize = 4;
const FEATURE_BITS_BYTE: usize = 8;
const TOKEN_DATA_START: usize = 11;
const JOB_DATA_START: usize = 29;
const PROFILE_DATA_START: usize = 47;
const BODY_KEY_START: usize = 66;
const NANOS_DATA_START: usize = 104;
const VOLUME_DEVICE_START: usize = 114;
const ROOT_GENERATION_BYTE: usize = 147;
const PRESERVE_POLICY_BYTE: usize = 184;
const DIRECTORIES_ARRAY_START: usize = 186;
const SIGNATURE_START: usize = BODY_START + BODY_LEN + 35 + 3;

#[test]
fn golden_bytes_and_repeated_signatures_agree() {
	let key = signing_key();
	let first = OwnerRecord::sign(manifest(), &key).expect("valid owner manifest");
	let repeated = OwnerRecord::sign(manifest(), &key).expect("repeat signing");
	assert_eq!(first, repeated);
	assert_eq!(first.as_bytes(), golden());
	let recorded = OwnerDigest::from_bytes(*blake3::hash(&golden()).as_bytes());
	assert_eq!(first.digest(), recorded);
	let decoded = decode(&golden()).expect("independent golden owner record");
	assert_eq!(decoded, first);
	assert_eq!(decoded.manifest(), &manifest());
	assert_eq!(decoded.verifying_key(), &key.verifying_key());
}

#[test]
fn a_valid_signature_from_an_untrusted_profile_is_refused() {
	let foreign_key = SigningKey::from_bytes(&[0x12; 32]);
	let foreign = OwnerRecord::sign(manifest(), &foreign_key).expect("valid foreign signature");
	assert_eq!(decode(foreign.as_bytes()), Err(OwnerError::UntrustedKey));
	let foreign_profile =
		OwnerProfileId::from_bytes([0x13; 16]).expect("nonnil profile identifier");
	assert_eq!(
		OwnerRecord::decode(&golden(), foreign_profile, &signing_key().verifying_key()),
		Err(OwnerError::UntrustedProfile),
	);
	let mut forged_body = body();
	forged_body[BODY_KEY_START..BODY_KEY_START + 32]
		.copy_from_slice(foreign_key.verifying_key().as_bytes());
	assert_eq!(decode(&resign(&forged_body)), Err(OwnerError::UntrustedKey));
}

#[test]
fn crypto_check_rejects_tampering_cross_domain_signatures_and_weak_keys() {
	let mut bad_signature = golden();
	bad_signature[SIGNATURE_START] ^= 1;
	assert_eq!(decode(&bad_signature), Err(OwnerError::InvalidSignature));

	let mut edited_body = golden();
	edited_body[BODY_START + TOKEN_DATA_START] ^= 1;
	assert_eq!(decode(&edited_body), Err(OwnerError::InvalidSignature));

	let signing_key = signing_key();
	let canonical_body = body();
	let wrong_signature = signing_key.sign(&canonical_body);
	let wrong_domain_message = envelope(
		&canonical_body,
		signing_key.verifying_key().to_bytes(),
		wrong_signature.to_bytes(),
	);
	assert_eq!(
		decode(&wrong_domain_message),
		Err(OwnerError::InvalidSignature)
	);

	let mut wrong_domain_code = golden();
	let domain_byte = wrong_domain_code.len() - 1;
	wrong_domain_code.splice(domain_byte.., [0x18, 32]);
	assert_eq!(decode(&wrong_domain_code), Err(OwnerError::WrongDomain));

	// The compressed Edwards identity is a weak public key. With R also the
	// identity and S zero, the naive verification equation is satisfied.
	let mut identity = [0; 32];
	identity[0] = 1;
	let mut weak_body = canonical_body;
	weak_body[BODY_KEY_START..BODY_KEY_START + 32].copy_from_slice(&identity);
	let mut weak_signature = [0; 64];
	weak_signature[0] = 1;
	let weak_key = VerifyingKey::from_bytes(&identity).expect("compressed Edwards identity");
	assert_eq!(
		OwnerRecord::decode(
			&envelope(&weak_body, identity, weak_signature),
			profile(),
			&weak_key
		),
		Err(OwnerError::InvalidSignature),
	);
}

#[test]
fn refuses_truncation_and_envelope_suffix() {
	let bytes = golden();
	for cut in 0..bytes.len() {
		assert!(decode(&bytes[..cut]).is_err(), "truncation at byte {cut}");
	}
	let mut suffixed = bytes;
	suffixed.push(0);
	assert_eq!(decode(&suffixed), Err(OwnerError::TrailingBytes));
}

#[test]
fn rejects_noncanonical_and_excessive_encodings() {
	let mut aliased_envelope = golden();
	// Encode the canonical one-byte body length as a two-byte integer.
	aliased_envelope.splice(2..3, [0x59, 0]);
	assert_eq!(decode(&aliased_envelope), Err(OwnerError::NonCanonical));

	let mut aliased_body = body();
	aliased_body.splice(FORMAT_MAJOR_BYTE..=FORMAT_MAJOR_BYTE, [0x18, 1]);
	assert_eq!(
		decode(&resign(&aliased_body)),
		Err(OwnerError::NonCanonical)
	);
	let mut trailing_body = body();
	trailing_body.push(0);
	assert_eq!(
		decode(&resign(&trailing_body)),
		Err(OwnerError::TrailingBytes)
	);

	let mut duplicate = body();
	duplicate[PROFILE_DATA_START - 2] = 2;
	assert_eq!(decode(&resign(&duplicate)), Err(OwnerError::InvalidCbor));
	let mut indefinite = golden();
	indefinite[0] = 0xbf;
	indefinite.push(0xff);
	assert_eq!(decode(&indefinite), Err(OwnerError::InvalidCbor));

	let mut giant_count = body();
	giant_count.splice(
		DIRECTORIES_ARRAY_START..,
		[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
	);
	assert_eq!(
		decode(&resign(&giant_count)),
		Err(OwnerError::InvalidDirectories)
	);
	assert_eq!(
		decode(&vec![0; MAX_OWNER_BYTES + 1]),
		Err(OwnerError::Length)
	);
	assert_eq!(
		decode(&vec![0; MAX_OWNER_BYTES]),
		Err(OwnerError::InvalidCbor)
	);
}

#[test]
fn signed_but_unsupported_fields_are_refused() {
	for (index, replacement, error) in [
		(FORMAT_MAJOR_BYTE, 2, OwnerError::UnsupportedVersion),
		(FEATURE_BITS_BYTE, 1, OwnerError::UnsupportedVersion),
		(JOB_DATA_START + 6, 0x4c, OwnerError::InvalidJob),
		(NANOS_DATA_START, 0x3c, OwnerError::InvalidTimestamp),
		(VOLUME_DEVICE_START, 8, OwnerError::VolumeMismatch),
		(ROOT_GENERATION_BYTE, 1, OwnerError::UnsupportedIdentity),
		(PRESERVE_POLICY_BYTE, 1, OwnerError::UnsupportedPolicy),
	] {
		let mut unsupported = body();
		unsupported[index] = replacement;
		assert_eq!(
			decode(&resign(&unsupported)),
			Err(error),
			"body byte {index}"
		);
	}

	let mut nil_profile = body();
	nil_profile[PROFILE_DATA_START..PROFILE_DATA_START + 16].fill(0);
	assert_eq!(
		decode(&resign(&nil_profile)),
		Err(OwnerError::InvalidProfile)
	);
	let mut job_as_token = body();
	job_as_token[TOKEN_DATA_START..TOKEN_DATA_START + 16].copy_from_slice(&JOB);
	assert_eq!(
		decode(&resign(&job_as_token)),
		Err(OwnerError::InvalidToken)
	);
}

#[test]
fn state_directories_admit_only_canonical_safe_components() {
	for directory_encoding in [
		&b"\x80"[..],                     // Empty list.
		&b"\x81\x61/"[..],                // Absolute path.
		&b"\x81\x62.."[..],               // Parent traversal.
		&b"\x81\x65a/stg"[..],            // Nested path.
		&b"\x81\x65root\0"[..],           // NUL byte.
		&b"\x81\x65other"[..],            // Unallocated name.
		&b"\x82\x65stage\x65stage"[..],   // Duplicate.
		&b"\x82\x65stage\x67journal"[..], // Descending order.
	] {
		let mut invalid = body();
		invalid.splice(
			DIRECTORIES_ARRAY_START..,
			directory_encoding.iter().copied(),
		);
		assert_eq!(
			decode(&resign(&invalid)),
			Err(OwnerError::InvalidDirectories),
			"{directory_encoding:?}"
		);
	}
}

#[test]
fn signing_refuses_invalid_claims_and_debug_elides_protected_bytes() {
	let record = OwnerRecord::sign(manifest(), &signing_key()).expect("valid owner manifest");
	assert_eq!(
		format!("{:?}", record.manifest().token),
		"OwnerToken(<redacted>)"
	);
	let debug = format!("{record:?}");
	assert!(debug.contains("OwnerToken(<redacted>)"));
	assert!(!debug.contains("204, 204"));
	assert!(!debug.contains("bytes:"));

	assert_eq!(
		OwnerToken::from_bytes([0; 16]),
		Err(OwnerError::InvalidToken)
	);
	assert_eq!(
		OwnerTimestamp::new(0, 1_000_000_000),
		Err(OwnerError::InvalidTimestamp)
	);
	let mut invalid = manifest();
	invalid.destination_device = u64::MAX;
	assert_eq!(
		OwnerRecord::sign(invalid, &signing_key()),
		Err(OwnerError::VolumeMismatch)
	);

	let mut invalid = manifest();
	invalid.directories.reverse();
	assert_eq!(
		OwnerRecord::sign(invalid, &signing_key()),
		Err(OwnerError::InvalidDirectories)
	);
}

#[test]
fn extreme_observations_and_all_known_directories_roundtrip() {
	for seconds in [i64::MIN, i64::MAX] {
		let mut claims = manifest();
		claims.created = OwnerTimestamp::new(seconds, 0).expect("valid second");
		claims.destination_device = u64::MAX;
		claims.state_root = LinuxFileIdentity::new(u64::MAX, u64::MAX);
		claims.directories = vec![
			OwnerStateDirectory::Checkpoints,
			OwnerStateDirectory::Journal,
			OwnerStateDirectory::Receipts,
			OwnerStateDirectory::Stage,
			OwnerStateDirectory::Versions,
		];
		let record = OwnerRecord::sign(claims, &signing_key()).expect("valid owner manifest");
		assert_eq!(decode(record.as_bytes()), Ok(record));
	}
}

fn signing_key() -> SigningKey {
	SigningKey::from_bytes(&[0x11; 32])
}

fn profile() -> OwnerProfileId {
	OwnerProfileId::from_bytes(PROFILE).expect("golden profile ID")
}

fn manifest() -> OwnerManifest {
	OwnerManifest {
		token: OwnerToken::from_bytes(TOKEN).expect("golden token"),
		job: JournalJobId::from_bytes(JOB).expect("golden UUIDv7"),
		profile: profile(),
		created: OwnerTimestamp::new(-1, 999_999_999).expect("golden timestamp"),
		destination_device: 7,
		state_root: LinuxFileIdentity::new(7, 9),
		plan_digest: PlanDigest::from_bytes([0x33; 32]),
		directories: vec![
			OwnerStateDirectory::Checkpoints,
			OwnerStateDirectory::Journal,
			OwnerStateDirectory::Stage,
		],
	}
}

fn golden() -> Vec<u8> {
	let (pairs, remainder) = GOLDEN_HEX.as_bytes().as_chunks::<2>();
	assert!(remainder.is_empty(), "hex fixture contains complete octets");
	pairs
		.iter()
		.map(|pair| {
			let text = std::str::from_utf8(pair).expect("ASCII hex fixture");
			u8::from_str_radix(text, 16).expect("hex fixture octet")
		})
		.collect()
}

fn decode(bytes: &[u8]) -> Result<OwnerRecord, OwnerError> {
	OwnerRecord::decode(bytes, profile(), &signing_key().verifying_key())
}

fn body() -> Vec<u8> {
	golden()[BODY_START..BODY_START + BODY_LEN].to_vec()
}

fn resign(body: &[u8]) -> Vec<u8> {
	let key = signing_key();
	let signature = key.sign(&[DOMAIN, body].concat());
	envelope(body, key.verifying_key().to_bytes(), signature.to_bytes())
}

fn envelope(body: &[u8], key: [u8; 32], signature: [u8; 64]) -> Vec<u8> {
	let length = u8::try_from(body.len()).expect("test fixture uses one-byte length");
	[
		&[0xa4, 0x00, 0x58, length],
		body,
		&[0x01, 0x58, 0x20],
		&key,
		&[0x02, 0x58, 0x40],
		&signature,
		&[0x03, 0x01],
	]
	.concat()
}
