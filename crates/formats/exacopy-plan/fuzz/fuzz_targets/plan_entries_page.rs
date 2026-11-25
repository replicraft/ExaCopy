//! Exercises public reference parsing and the referenced PlanEntries leaf parser.
#![no_main]
#![forbid(unsafe_code)]

use exacopy_plan::{
	DocumentError, DocumentPageKind, DocumentRef, MAX_DOCUMENT_PAGE_BYTES, MAX_PLAN_IDENTITY_BYTES,
	PlanEntriesPage,
};
use libfuzzer_sys::fuzz_target;

const PAGE_KIND: DocumentPageKind = DocumentPageKind::PlanEntries;
const ADDRESSED_PLAN_PAGE: &[u8] = b"ExaCopy/document-page/v1\0\x01\x00";

fn check_reference(input: &[u8]) {
	if let Ok(reference) = DocumentRef::from_canonical_cbor(input) {
		assert!((1..=MAX_DOCUMENT_PAGE_BYTES).contains(&(reference.encoded_bytes() as usize)));
		assert_eq!(reference.canonical_cbor(), input);
		assert_eq!(
			DocumentRef::new(
				reference.page_id(),
				reference.kind(),
				u64::from(reference.encoded_bytes()),
				reference.item_count(),
			),
			Ok(reference)
		);
	}
}

fn check_page(input: &[u8]) {
	if input.is_empty() || input.len() > MAX_DOCUMENT_PAGE_BYTES {
		let placeholder = DocumentRef::new([0; 32], PAGE_KIND, 1, 1).unwrap();
		let expected = if input.is_empty() {
			DocumentError::LengthMismatch
		} else {
			DocumentError::Size
		};
		assert_eq!(
			PlanEntriesPage::from_canonical_cbor(placeholder, input),
			Err(expected)
		);
		return;
	}

	let length = input.len() as u64;
	// Address the original bytes, including malformed representations. That permits
	// reaching the CBOR parser even when a mutation changed every byte.
	let page_digest = *blake3::Hasher::new()
		.update(ADDRESSED_PLAN_PAGE)
		.update(&length.to_le_bytes())
		.update(input)
		.finalize()
		.as_bytes();
	let reference = DocumentRef::new(page_digest, PAGE_KIND, length, 1).unwrap();
	let Ok(page) = PlanEntriesPage::from_canonical_cbor(reference, input) else {
		return;
	};

	let entry = page.entry();
	assert!(!entry.entry_id.is_nil() && !entry.source_view_id.is_nil());
	assert!(entry.source != entry.destination);
	for path in [entry.source, entry.destination] {
		assert!(!path.root_id.is_nil());
		assert!((1..=255).contains(&path.basename.len()));
		assert!(!matches!(path.basename, b"." | b".."));
		assert!(!path.basename.iter().any(|byte| matches!(byte, b'/' | 0)));
	}
	if let Some(identity) = entry.source_identity {
		assert!((1..=MAX_PLAN_IDENTITY_BYTES).contains(&identity.volume_id.len()));
		assert!((1..=MAX_PLAN_IDENTITY_BYTES).contains(&identity.object_id.len()));
		if let Some(generation) = identity.generation {
			assert!((1..=MAX_PLAN_IDENTITY_BYTES).contains(&generation.len()));
		}
	}
	assert!(entry.stream_length <= i64::MAX as u64);
	assert_eq!(page.canonical_cbor(), input);
	assert_eq!(page.document_ref(), reference);

	let mut different = page_digest;
	different[0] ^= 1;
	let wrong = DocumentRef::new(different, PAGE_KIND, length, 1).unwrap();
	assert_eq!(
		PlanEntriesPage::from_canonical_cbor(wrong, input),
		Err(DocumentError::DigestMismatch)
	);
}

fuzz_target!(|input: &[u8]| {
	check_reference(input);
	check_page(input);
});
