use ed25519_dalek::VerifyingKey;
use exacopy_journal::{ApplyQualificationDigest, OwnerTimestamp};

use super::record::{Qualification, RECORD_BYTES, verify};
use super::{LocalApplyQualificationEnrollment, QualifiedPublicApplyProposalError as Failure};

const ATTESTOR: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const OWNER: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const BODY: &str = include_str!("vectors/accepted.hex");
const DIGEST: &str = include_str!("vectors/accepted.digest");

#[test]
fn authenticates_the_frozen_local_record_and_distinct_native_roles() {
	let record = selected(BODY, DIGEST).unwrap();
	assert_eq!(record.image_length, 27);
	assert_eq!(
		record.image,
		hex::<32>("4bf8cce92e90c4c7a2384e618a7b75c3d2848024b0a575e89706fd8c9c18be44")
	);
	assert_eq!(record.environment.boot_id, [0x44; 16]);
	assert_eq!(record.environment.mount_namespace, 101);
	assert_eq!(record.environment.unique_mount, 202);
	assert_eq!(record.environment.device, 0xfc01);
	assert_eq!(
		(*record.source.alias.as_bytes(), record.source.inode),
		(hex::<16>("55555555555545559555555555555555"), 9001)
	);
	assert_eq!(
		(
			*record.destination.alias.as_bytes(),
			record.destination.inode
		),
		(hex::<16>("6666666666664666a666666666666666"), 9002)
	);
	assert_eq!(record.owner_profile, [0x77; 16]);
	assert_eq!(record.plan, [0x88; 32]);
	assert_eq!(record.entry, [0x99; 16]);
	assert_eq!(record.metadata, [0xaa; 32]);
}

#[test]
fn refuses_foreign_purpose_even_with_the_selected_exact_record_digest() {
	assert!(matches!(
		selected(
			include_str!("vectors/wrong-purpose.hex"),
			include_str!("vectors/wrong-purpose.digest"),
		),
		Err(Failure::Signature)
	));
	for (bytes, digest) in [
		(
			include_str!("vectors/empty-image.hex"),
			include_str!("vectors/empty-image.digest"),
		),
		(
			include_str!("vectors/empty-window.hex"),
			include_str!("vectors/empty-window.digest"),
		),
		(
			include_str!("vectors/invalid-root-alias.hex"),
			include_str!("vectors/invalid-root-alias.digest"),
		),
	] {
		assert!(matches!(selected(bytes, digest), Err(Failure::Record)));
	}
}

#[test]
fn refuses_wrong_selection_signer_and_nonexact_extents() {
	let bytes = hex::<RECORD_BYTES>(BODY);
	let attestor = key(ATTESTOR);
	let owner = key(OWNER);
	let mut selection = enrollment(&attestor, DIGEST);
	assert!(matches!(
		verify(&bytes[..RECORD_BYTES - 1], &selection, &owner),
		Err(Failure::Record)
	));
	let mut trailing = bytes.to_vec();
	trailing.push(0);
	assert!(matches!(
		verify(&trailing, &selection, &owner),
		Err(Failure::Record)
	));
	assert!(matches!(
		verify(&bytes, &selection, &attestor),
		Err(Failure::Selection)
	));
	let reused_owner = hex::<RECORD_BYTES>(include_str!("vectors/same-role-key.hex"));
	let selected_reused = enrollment(&attestor, include_str!("vectors/same-role-key.digest"));
	assert!(matches!(
		verify(&reused_owner, &selected_reused, &attestor),
		Err(Failure::Selection)
	));
	selection.attestor_id[0] ^= 1;
	assert!(matches!(
		verify(&bytes, &selection, &owner),
		Err(Failure::Selection)
	));
	selection.attestor_id[0] ^= 1;
	selection.record_digest = ApplyQualificationDigest::from_bytes([0x51; 32]);
	assert!(matches!(
		verify(&bytes, &selection, &owner),
		Err(Failure::Selection)
	));
}

#[test]
fn time_selection_requires_the_original_plan_and_record_windows() {
	let record = selected(BODY, DIGEST).unwrap();
	let time = |seconds, nanos| OwnerTimestamp::new(seconds, nanos).unwrap();
	let plan = time(1_800_000_010, 20);
	assert!(record.check_time(time(1_800_000_000, 0), plan).is_ok());
	assert!(record.check_time(time(1_800_000_010, 19), plan).is_ok());
	for (current, expiry) in [
		(time(1_799_999_999, 999_999_999), plan),
		(plan, plan),
		(time(1_800_000_100, 0), time(1_800_000_200, 0)),
	] {
		assert!(matches!(
			record.check_time(current, expiry),
			Err(Failure::Time)
		));
	}
}

fn selected(record: &str, digest: &str) -> Result<Qualification, Failure> {
	let attestor = key(ATTESTOR);
	verify(
		&hex::<RECORD_BYTES>(record),
		&enrollment(&attestor, digest),
		&key(OWNER),
	)
}

fn enrollment<'key>(
	attestor_key: &'key VerifyingKey,
	digest: &str,
) -> LocalApplyQualificationEnrollment<'key> {
	LocalApplyQualificationEnrollment {
		record_path: std::path::Path::new("/not-opened-by-vector-tests"),
		record_digest: ApplyQualificationDigest::from_bytes(hex(digest)),
		attestor_id: [0x11; 16],
		attestor_key,
	}
}

fn key(text: &str) -> VerifyingKey {
	VerifyingKey::from_bytes(&hex(text)).unwrap()
}

fn hex<const N: usize>(text: &str) -> [u8; N] {
	let text = text.trim();
	assert_eq!(text.len(), 2 * N);
	std::array::from_fn(|index| u8::from_str_radix(&text[2 * index..2 * index + 2], 16).unwrap())
}
