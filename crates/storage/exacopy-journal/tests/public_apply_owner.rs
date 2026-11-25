//! Signed public-apply evidence and legacy reader separation.

use ed25519_dalek::{Signer, SigningKey};
use exacopy_endpoint::MAX_FILE_LENGTH;
use exacopy_journal::{
	ApplyMetadataPolicyDigest, ApplyRequestedDurability, ApprovedPublicPlanDigest,
	ApprovedStreamDigest, DarwinOwnerRecord, JournalEntryId, JournalEpoch, JournalJobId,
	LinuxFileIdentity, MAX_OWNER_BYTES, OwnerDigest, OwnerError, OwnerManifest, OwnerProfileId,
	OwnerRecord, OwnerStateDirectory, OwnerTimestamp, OwnerToken, PlanDigest, PublicApplyBinding,
	PublicApplyOwnerManifest, PublicApplyOwnerRecord, PublicPlanEntryId, RootCapabilityId,
	StreamLength,
};
use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};

const DOMAIN: &[u8] = b"ExaCopy/owner/linux-public-apply/v1\0";
const DOMAIN_CODE: u8 = 3;
const PROFILE: [u8; 16] = [0xa2; 16];
const TOKEN: [u8; 16] = [0xa1; 16];
const PRIVATE_PLAN: [u8; 32] = [0xa3; 32];
const PUBLIC_PLAN: [u8; 32] = [0xb1; 32];
const PUBLIC_ENTRY: [u8; 16] = [0xb2; 16];
const PRIVATE_ENTRY: [u8; 16] = [0xb3; 16];
const STREAM: [u8; 32] = [0xb7; 32];
const POLICY: [u8; 32] = [0xb8; 32];
const EPOCH: u64 = 24;
const LENGTH: u64 = 65_536;
const JOB: [u8; 16] = [
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x7c, 0xde, 0x8f, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
];
const SOURCE_ROOT: [u8; 16] = [
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x4c, 0xde, 0x8f, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x01,
];
const DESTINATION_ROOT: [u8; 16] = [
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x4c, 0xde, 0x8f, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x02,
];

#[test]
fn independent_vector_fixes_the_signed_projection_and_legacy_boundary() {
	let expected = golden();
	let signed = PublicApplyOwnerRecord::sign(manifest(), &signing_key()).unwrap();
	assert_eq!(signed.as_bytes(), expected);
	let decoded = decode(&expected).unwrap();
	assert_eq!(decoded, signed);
	assert_eq!(decoded.manifest(), &manifest());
	assert_eq!(
		decoded.digest(),
		OwnerDigest::from_bytes(*blake3::hash(&expected).as_bytes())
	);

	let key = signing_key().verifying_key();
	assert_eq!(
		OwnerRecord::decode(&expected, profile(), &key),
		Err(OwnerError::WrongDomain)
	);
	assert_eq!(
		DarwinOwnerRecord::decode(&expected, profile(), &key),
		Err(OwnerError::WrongDomain)
	);
	let legacy = OwnerRecord::sign(manifest().owner, &signing_key()).unwrap();
	assert_eq!(decode(legacy.as_bytes()), Err(OwnerError::WrongDomain));
	assert_eq!(
		decode(&envelope(&legacy_body(&expected), DOMAIN)),
		Err(OwnerError::InvalidCbor),
		"A legacy manifest alone cannot satisfy the public-apply owner shape"
	);
}

#[test]
fn each_selected_field_is_in_the_authenticated_body() {
	let expected = golden();
	let body_start = locate(&expected, &signed_body(&expected));
	let components: &[&[u8]] = &[
		&JOB,
		&PROFILE,
		&TOKEN,
		&PRIVATE_PLAN,
		&PUBLIC_PLAN,
		&PUBLIC_ENTRY,
		&PRIVATE_ENTRY,
		&SOURCE_ROOT,
		&DESTINATION_ROOT,
		&STREAM,
		&POLICY,
		&[0x03, 0x18, 0x18, 0x04],
		&[0x06, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x07],
		&[0x05, 0xa2, 0x00, 0x21, 0x01],
		&[0x09, 0x82, 0x20, 0x1a, 0x07, 0x5b, 0xcd, 0x15, 0x0a],
	];
	for component in components {
		let offset = body_start + locate(&signed_body(&expected), component);
		let mut altered = expected.clone();
		altered[offset] ^= 1;
		assert_eq!(
			decode(&altered),
			Err(OwnerError::InvalidSignature),
			"{component:?}"
		);
	}
}

#[test]
fn independent_profile_and_signature_domain_are_mandatory() {
	let expected = golden();
	let key = signing_key();
	let foreign_profile = OwnerProfileId::from_bytes([0xee; 16]).unwrap();
	assert_eq!(
		PublicApplyOwnerRecord::decode(&expected, foreign_profile, &key.verifying_key()),
		Err(OwnerError::UntrustedProfile),
	);
	let foreign_key = SigningKey::from_bytes(&[0xee; 32]);
	let foreign = PublicApplyOwnerRecord::sign(manifest(), &foreign_key).unwrap();
	assert_eq!(decode(foreign.as_bytes()), Err(OwnerError::UntrustedKey));

	let body = signed_body(&expected);
	for wrong_prefix in [b"ExaCopy/owner/v1\0".as_slice(), b"ExaCopy/plan/v1\0", b""] {
		assert_eq!(
			decode(&envelope(&body, wrong_prefix)),
			Err(OwnerError::InvalidSignature),
		);
	}

	let mut relabelled = expected;
	*relabelled.last_mut().unwrap() = 1;
	assert!(OwnerRecord::decode(&relabelled, profile(), &key.verifying_key()).is_err());
}

#[test]
fn authenticated_malformed_binding_is_still_refused() {
	let body = signed_body(&golden());
	let cases: &[(&[u8], &[u8], OwnerError)] = &[
		(
			&[0xa3, 0x00, 0xa3, 0x00, 0x01, 0x01, 0x00, 0x02, 0x01],
			&[0xa3, 0x00, 0xa3, 0x00, 0x01, 0x01, 0x00, 0x02, 0x00],
			OwnerError::UnsupportedVersion,
		),
		(
			&[0x03, 0x18, 0x18, 0x04],
			&[0x03, 0x00, 0x04],
			OwnerError::InvalidApplyEpoch,
		),
		(
			&[0x03, 0x18, 0x18, 0x04],
			&[0x03, 0x19, 0x00, 0x18, 0x04],
			OwnerError::NonCanonical,
		),
		(&PUBLIC_ENTRY, &[0; 16], OwnerError::InvalidApplyEntry),
		(&PRIVATE_ENTRY, &[0; 16], OwnerError::InvalidApplyEntry),
		(&SOURCE_ROOT, &[0; 16], OwnerError::InvalidApplyRoot),
		(
			&[0x06, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x07],
			&[0x06, 0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x07],
			OwnerError::InvalidApplyLength,
		),
		(
			&[0x09, 0x82, 0x20, 0x1a, 0x07, 0x5b, 0xcd, 0x15, 0x0a],
			&[0x09, 0x82, 0x21, 0x1a, 0x3b, 0x9a, 0xc9, 0xff, 0x0a],
			OwnerError::InvalidApplyExpiry,
		),
		(
			&[0x09, 0x82, 0x20, 0x1a, 0x07, 0x5b, 0xcd, 0x15, 0x0a, 0x00],
			&[0x09, 0x82, 0x20, 0x1a, 0x07, 0x5b, 0xcd, 0x15, 0x0a, 0x01],
			OwnerError::UnsupportedApplyDurability,
		),
	];
	for &(needle, replacement, error) in cases {
		let mut altered = body.clone();
		let offset = locate(&altered, needle);
		altered.splice(offset..offset + needle.len(), replacement.iter().copied());
		assert_eq!(decode(&envelope(&altered, DOMAIN)), Err(error), "{error:?}");
	}

	let mut altered = body;
	altered.push(0);
	assert_eq!(
		decode(&envelope(&altered, DOMAIN)),
		Err(OwnerError::TrailingBytes)
	);
}

#[test]
fn bounded_endpoint_values_and_optional_expiry_round_trip() {
	let mut claims = manifest();
	claims.binding.epoch = JournalEpoch::new(u64::MAX);
	claims.binding.source_root = claims.binding.destination_root;
	claims.binding.stream_length = StreamLength::new(MAX_FILE_LENGTH).unwrap();
	claims.owner.state_root = LinuxFileIdentity::new(u64::MAX, u64::MAX);
	claims.owner.destination_device = u64::MAX;
	claims.owner.created = OwnerTimestamp::new(i64::MIN, 999_999_999).unwrap();
	claims.owner.directories.push(OwnerStateDirectory::Versions);
	claims.binding.expires_at = Some(OwnerTimestamp::new(i64::MAX, 999_999_999).unwrap());
	let signed = PublicApplyOwnerRecord::sign(claims.clone(), &signing_key()).unwrap();
	assert_eq!(decode(signed.as_bytes()).unwrap().manifest(), &claims);
	assert_eq!(
		OwnerRecord::decode(signed.as_bytes(), profile(), &signing_key().verifying_key()),
		Err(OwnerError::WrongDomain),
	);

	claims.binding.expires_at = None;
	claims.binding.stream_length = StreamLength::new(0).unwrap();
	let signed = PublicApplyOwnerRecord::sign(claims.clone(), &signing_key()).unwrap();
	assert_eq!(decode(signed.as_bytes()).unwrap().manifest(), &claims);
}

#[test]
fn signing_rejects_nonpositive_admission_windows_and_invalid_attempts() {
	let mut claims = manifest();
	let key = signing_key();
	claims.owner.created = OwnerTimestamp::new(7, 10).unwrap();
	for expiry in [
		OwnerTimestamp::new(6, 11).unwrap(),
		OwnerTimestamp::new(7, 10).unwrap(),
	] {
		claims.binding.expires_at = Some(expiry);
		assert_eq!(
			PublicApplyOwnerRecord::sign(claims.clone(), &key),
			Err(OwnerError::InvalidApplyExpiry),
		);
	}
	claims.binding.expires_at = Some(OwnerTimestamp::new(7, 11).unwrap());
	assert!(PublicApplyOwnerRecord::sign(claims.clone(), &key).is_ok());
	claims.binding.epoch = JournalEpoch::new(0);
	assert_eq!(
		PublicApplyOwnerRecord::sign(claims.clone(), &key),
		Err(OwnerError::InvalidApplyEpoch),
	);
	claims.binding.epoch = JournalEpoch::new(1);
	claims.binding.private_entry = JournalEntryId::from_bytes([0; 16]);
	assert_eq!(
		PublicApplyOwnerRecord::sign(claims, &key),
		Err(OwnerError::InvalidApplyEntry)
	);
}

#[test]
fn truncated_excessive_and_noncanonical_envelopes_are_refused() {
	let expected = golden();
	for cut in 0..expected.len() {
		assert!(decode(&expected[..cut]).is_err(), "truncation at {cut}");
	}
	let mut suffixed = expected.clone();
	suffixed.push(0);
	assert_eq!(decode(&suffixed), Err(OwnerError::TrailingBytes));

	let mut nonminimal_domain = expected;
	nonminimal_domain.pop();
	nonminimal_domain.extend([0x18, DOMAIN_CODE]);
	assert_eq!(decode(&nonminimal_domain), Err(OwnerError::NonCanonical));
	assert_eq!(
		decode(&vec![0; MAX_OWNER_BYTES + 1]),
		Err(OwnerError::Length)
	);
}

fn manifest() -> PublicApplyOwnerManifest {
	PublicApplyOwnerManifest {
		owner: OwnerManifest {
			token: OwnerToken::from_bytes(TOKEN).unwrap(),
			job: JournalJobId::from_bytes(JOB).unwrap(),
			profile: profile(),
			created: OwnerTimestamp::new(-2, 999_999_999).unwrap(),
			destination_device: 7,
			state_root: LinuxFileIdentity::new(7, 9),
			plan_digest: PlanDigest::from_bytes(PRIVATE_PLAN),
			directories: vec![
				OwnerStateDirectory::Checkpoints,
				OwnerStateDirectory::Journal,
				OwnerStateDirectory::Receipts,
				OwnerStateDirectory::Stage,
			],
		},
		binding: PublicApplyBinding {
			public_plan: ApprovedPublicPlanDigest::from_bytes(PUBLIC_PLAN),
			public_entry: PublicPlanEntryId::from_bytes(PUBLIC_ENTRY).unwrap(),
			private_entry: JournalEntryId::from_bytes(PRIVATE_ENTRY),
			epoch: JournalEpoch::new(EPOCH),
			source_root: RootCapabilityId::from_bytes(SOURCE_ROOT).unwrap(),
			destination_root: RootCapabilityId::from_bytes(DESTINATION_ROOT).unwrap(),
			stream_length: StreamLength::new(LENGTH).unwrap(),
			stream_digest: ApprovedStreamDigest::from_bytes(STREAM),
			metadata_policy: ApplyMetadataPolicyDigest::from_bytes(POLICY),
			expires_at: Some(OwnerTimestamp::new(-1, 123_456_789).unwrap()),
			requested_durability: ApplyRequestedDurability::ProcessCrash,
		},
	}
}

fn signing_key() -> SigningKey {
	SigningKey::from_bytes(&[0x42; 32])
}

fn profile() -> OwnerProfileId {
	OwnerProfileId::from_bytes(PROFILE).unwrap()
}

fn decode(bytes: &[u8]) -> Result<PublicApplyOwnerRecord, OwnerError> {
	PublicApplyOwnerRecord::decode(bytes, profile(), &signing_key().verifying_key())
}

fn golden() -> Vec<u8> {
	// Canonical CBOR constructed independently in Python and signed with OpenSSL Ed25519.
	include_str!("public_apply_owner.hex")
		.split_ascii_whitespace()
		.flat_map(|line| {
			(0..line.len())
				.step_by(2)
				.map(|pos| u8::from_str_radix(&line[pos..pos + 2], 16).unwrap())
		})
		.collect()
}

fn locate(haystack: &[u8], needle: &[u8]) -> usize {
	let mut matches = haystack
		.windows(needle.len())
		.enumerate()
		.filter(|(_, window)| *window == needle);
	let offset = matches.next().unwrap().0;
	assert!(matches.next().is_none(), "ambiguous fixture value");
	offset
}

fn signed_body(bytes: &[u8]) -> Vec<u8> {
	let mut decoder = Decoder::new(bytes);
	assert_eq!(decoder.map().unwrap(), Some(4));
	assert_eq!(decoder.u8().unwrap(), 0);
	decoder.bytes().unwrap().to_vec()
}

fn legacy_body(bytes: &[u8]) -> Vec<u8> {
	let body = signed_body(bytes);
	let legacy_start = locate(&body, &[0x01, 0x58, 0xde, 0xab]);
	let mut decoder = Decoder::new(&body[legacy_start + 1..]);
	decoder.bytes().unwrap().to_vec()
}

fn envelope(body: &[u8], prefix: &[u8]) -> Vec<u8> {
	let signer = signing_key();
	let signature = signer.sign(&[prefix, body].concat());
	let mut writer = Encoder::new(Cursor::new([0; 1024]));
	writer
		.map(4)
		.unwrap()
		.u8(0)
		.unwrap()
		.bytes(body)
		.unwrap()
		.u8(1)
		.unwrap()
		.bytes(signer.verifying_key().as_bytes())
		.unwrap()
		.u8(2)
		.unwrap()
		.bytes(&signature.to_bytes())
		.unwrap()
		.u8(3)
		.unwrap()
		.u8(DOMAIN_CODE)
		.unwrap();
	let encoded = writer.into_writer();
	encoded.get_ref()[..encoded.position()].to_vec()
}
