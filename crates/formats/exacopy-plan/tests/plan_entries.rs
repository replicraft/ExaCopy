//! Independent portable vectors and fail-closed admission for public plan pages.

use exacopy_plan::{
	DocumentError, DocumentPageKind, DocumentRef, MAX_DOCUMENT_PAGE_BYTES, MAX_PLAN_IDENTITY_BYTES,
	PlanEntriesPage, PlanIdentityPlatform, PlanSourceIdentity,
};
use uuid::Uuid;

const EMPTY_PAGE: &[u8] =
	include_bytes!("../verification/plan_entries/vectors/empty-file.page.cbor");
const EMPTY_REF: &[u8] = include_bytes!("../verification/plan_entries/vectors/empty-file.ref.cbor");
const IDENTITY_PAGE: &[u8] =
	include_bytes!("../verification/plan_entries/vectors/observed-identity.page.cbor");
const IDENTITY_REF: &[u8] =
	include_bytes!("../verification/plan_entries/vectors/observed-identity.ref.cbor");

fn reference_fixture() -> DocumentRef {
	DocumentRef::from_canonical_cbor(EMPTY_REF).unwrap()
}

fn valid_page() -> PlanEntriesPage<'static> {
	PlanEntriesPage::from_canonical_cbor(reference_fixture(), EMPTY_PAGE).unwrap()
}

fn matching_test_ref(body: &[u8], count: u64) -> DocumentRef {
	// Form a reference to arbitrary input to exercise the parser beyond the digest gate.
	let mut framed = b"ExaCopy/document-page/v1\0\x01\x00".to_vec();
	framed.extend_from_slice(&(body.len() as u64).to_le_bytes());
	framed.extend_from_slice(body);
	DocumentRef::new(
		*blake3::hash(&framed).as_bytes(),
		DocumentPageKind::PlanEntries,
		body.len() as u64,
		count,
	)
	.unwrap()
}

#[test]
fn independent_canonical_vectors_bind_zero_length_entry_and_opaque_identity() {
	for (raw_page, raw_ref) in [(EMPTY_PAGE, EMPTY_REF), (IDENTITY_PAGE, IDENTITY_REF)] {
		let reference = DocumentRef::from_canonical_cbor(raw_ref).unwrap();
		let page = PlanEntriesPage::from_canonical_cbor(reference, raw_page).unwrap();
		assert_eq!(page.canonical_cbor(), raw_page);
		assert_eq!(page.document_ref(), reference);
		assert_eq!(reference.canonical_cbor(), raw_ref);
		assert_eq!(reference.item_count(), 1);
		assert_eq!(reference.encoded_bytes() as usize, raw_page.len());
		assert_eq!(page.entry().stream_length, 0);
		assert_eq!(page.entry().source.basename, b"\xff.bin");
		assert_eq!(page.entry().destination.basename, b"new.bin");
	}
	assert!(valid_page().entry().source_identity.is_none());
	let reference = DocumentRef::from_canonical_cbor(IDENTITY_REF).unwrap();
	let observed = PlanEntriesPage::from_canonical_cbor(reference, IDENTITY_PAGE)
		.unwrap()
		.entry();
	let identity = observed.source_identity.unwrap();
	assert_eq!(identity.platform, PlanIdentityPlatform::Linux);
	assert_eq!(identity.volume_id, b"v\0");
	assert_eq!(identity.object_id, b"\x80file");
	assert_eq!(identity.generation, Some(b"g".as_slice()));
	assert_eq!(observed.estimated_working_bytes, 4_294_967_297);
}

#[test]
fn document_reference_rejects_other_kind_and_wrong_digest() {
	let expected = reference_fixture();
	let other_kind = DocumentRef::new(
		expected.page_id(),
		DocumentPageKind::ManifestEntries,
		u64::from(expected.encoded_bytes()),
		1,
	)
	.unwrap();
	assert_eq!(
		PlanEntriesPage::from_canonical_cbor(other_kind, EMPTY_PAGE),
		Err(DocumentError::WrongKind)
	);

	let mut another_domain = b"ExaCopy/repository-object/v1\0".to_vec();
	another_domain.extend_from_slice(EMPTY_PAGE);
	let wrong_domain = DocumentRef::new(
		*blake3::hash(&another_domain).as_bytes(),
		DocumentPageKind::PlanEntries,
		u64::from(expected.encoded_bytes()),
		1,
	)
	.unwrap();
	assert_eq!(
		PlanEntriesPage::from_canonical_cbor(wrong_domain, EMPTY_PAGE),
		Err(DocumentError::DigestMismatch)
	);

	let wrong_count = DocumentRef::new(
		expected.page_id(),
		expected.kind(),
		u64::from(expected.encoded_bytes()),
		0,
	)
	.unwrap();
	assert_eq!(
		PlanEntriesPage::from_canonical_cbor(wrong_count, EMPTY_PAGE),
		Err(DocumentError::CountMismatch)
	);
	let truncated = &EMPTY_PAGE[..EMPTY_PAGE.len() - 1];
	assert_eq!(
		PlanEntriesPage::from_canonical_cbor(expected, truncated),
		Err(DocumentError::LengthMismatch)
	);
	assert_eq!(
		PlanEntriesPage::from_canonical_cbor(expected, &vec![0; MAX_DOCUMENT_PAGE_BYTES + 1]),
		Err(DocumentError::Size)
	);
	assert!(PlanEntriesPage::from_canonical_cbor(expected, EMPTY_PAGE).is_ok());
}

#[test]
fn fresh_digest_cannot_make_malformed_or_noncanonical_input_admissible() {
	for end in 1..EMPTY_PAGE.len() {
		let prefix = &EMPTY_PAGE[..end];
		assert!(
			PlanEntriesPage::from_canonical_cbor(matching_test_ref(prefix, 1), prefix).is_err()
		);
	}
	let mut trailing = EMPTY_PAGE.to_vec();
	trailing.push(0);
	let mut long_key = EMPTY_PAGE.to_vec();
	long_key.splice(1..2, [0x18, 0]);
	for noncanonical in [trailing, long_key] {
		assert_eq!(
			PlanEntriesPage::from_canonical_cbor(
				matching_test_ref(&noncanonical, 1),
				&noncanonical
			),
			Err(DocumentError::NonCanonical)
		);
	}
}

#[test]
fn page_format_and_profile_mismatches_are_fail_closed() {
	assert_eq!(&EMPTY_PAGE[..10], &[0xa6, 0, 0x82, 1, 0, 1, 1, 2, 0, 3]);
	for (offset, byte, expected) in [
		(3, 2, DocumentError::Unsupported),     // Format major.
		(6, 2, DocumentError::WrongKind),       // Encoded page kind.
		(8, 1, DocumentError::Unsupported),     // Tree level.
		(10, 0x80, DocumentError::Unsupported), // Entries array.
		(EMPTY_PAGE.len() - 1, 0, DocumentError::CountMismatch),
	] {
		let mut input = EMPTY_PAGE.to_vec();
		input[offset] = byte;
		assert_eq!(
			PlanEntriesPage::from_canonical_cbor(matching_test_ref(&input, 1), &input),
			Err(expected)
		);
	}
	let offsets = [
		(&[9, 0, 10, 0xf6, 11][..], 1, 2), // Action becomes protected_replace.
		(&[9, 0, 10, 0xf6, 11][..], 3, 0xa0), // Explicit conflict.
		(&[6, 0xf6, 7, 0x81, 0xa4][..], 1, 0xa0), // Expected incumbent.
	];
	for (field, offset, byte) in offsets {
		let start = EMPTY_PAGE
			.windows(field.len())
			.position(|value| value == field)
			.unwrap();
		let mut input = EMPTY_PAGE.to_vec();
		input[start + offset] = byte;
		assert_eq!(
			PlanEntriesPage::from_canonical_cbor(matching_test_ref(&input, 1), &input),
			Err(DocumentError::Unsupported)
		);
	}
}

#[test]
fn input_bounds_preserve_exact_components_and_optional_identity() {
	let entry = valid_page().entry();
	for bad in [b"".as_slice(), b".", b"..", b"a/b", b"a\0b", &[b'a'; 256]] {
		let mut invalid = entry;
		invalid.source.basename = bad;
		assert_eq!(
			PlanEntriesPage::new(invalid),
			Err(DocumentError::InvalidEntry)
		);
	}
	for invalid in [
		exacopy_plan::PlanEntry {
			entry_id: Uuid::nil(),
			..entry
		},
		exacopy_plan::PlanEntry {
			destination: entry.source,
			..entry
		},
		exacopy_plan::PlanEntry {
			stream_length: i64::MAX as u64 + 1,
			..entry
		},
	] {
		assert_eq!(
			PlanEntriesPage::new(invalid),
			Err(DocumentError::InvalidEntry)
		);
	}

	let mut maximum = entry;
	maximum.source.basename = &[b'x'; 255];
	maximum.source_identity = Some(PlanSourceIdentity {
		platform: PlanIdentityPlatform::Macos,
		volume_id: &[b'v'; MAX_PLAN_IDENTITY_BYTES],
		object_id: b"object",
		generation: None,
	});
	maximum.stream_length = i64::MAX as u64;
	maximum.estimated_working_bytes = u64::MAX;
	let maximal = PlanEntriesPage::new(maximum).unwrap();
	let bytes = maximal.canonical_cbor();
	assert_eq!(
		PlanEntriesPage::from_canonical_cbor(maximal.document_ref(), &bytes),
		Ok(maximal)
	);
	maximum.source_identity.as_mut().unwrap().generation =
		Some(&[b'g'; MAX_PLAN_IDENTITY_BYTES + 1]);
	assert_eq!(
		PlanEntriesPage::new(maximum),
		Err(DocumentError::InvalidEntry)
	);
}

#[test]
fn document_reference_enforces_registered_limits_and_complete_cbor() {
	for kind in [
		DocumentPageKind::PlanEntries,
		DocumentPageKind::ManifestEntries,
		DocumentPageKind::DiffEntries,
		DocumentPageKind::ReceiptEntries,
		DocumentPageKind::PatchOperations,
		DocumentPageKind::MetadataEntries,
	] {
		let reference =
			DocumentRef::new([0; 32], kind, MAX_DOCUMENT_PAGE_BYTES as u64, u64::MAX).unwrap();
		assert_eq!(
			DocumentRef::from_canonical_cbor(&reference.canonical_cbor()),
			Ok(reference)
		);
	}
	for length in [0, MAX_DOCUMENT_PAGE_BYTES as u64 + 1, u64::MAX] {
		assert_eq!(
			DocumentRef::new([0; 32], DocumentPageKind::PlanEntries, length, 1),
			Err(DocumentError::Size)
		);
	}
	let mut unknown_kind = EMPTY_REF.to_vec();
	assert_eq!(&unknown_kind[36..38], &[1, 1]);
	unknown_kind[37] = 7;
	assert_eq!(
		DocumentRef::from_canonical_cbor(&unknown_kind),
		Err(DocumentError::Unsupported)
	);
	let mut trailing = EMPTY_REF.to_vec();
	trailing.push(0);
	assert_eq!(
		DocumentRef::from_canonical_cbor(&trailing),
		Err(DocumentError::NonCanonical)
	);
}
