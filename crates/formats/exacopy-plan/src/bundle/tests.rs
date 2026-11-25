use crate::{PlanEntry, PlanPath};
use uuid::Uuid;

use super::*;

fn page() -> PlanEntriesPage<'static> {
	let source = PlanPath {
		root_id: Uuid::from_u128(1),
		basename: b"one",
	};
	let destination = PlanPath {
		root_id: Uuid::from_u128(2),
		basename: b"two",
	};
	PlanEntriesPage::new(PlanEntry {
		entry_id: Uuid::from_u128(3),
		source,
		destination,
		source_view_id: Uuid::from_u128(4),
		source_identity: None,
		stream_length: 0,
		stream_digest: [5; 32],
		metadata_policy_digest: [6; 32],
		estimated_working_bytes: 0,
	})
	.unwrap()
}

#[test]
fn prepare_preserves_page_and_envelope_bytes_and_the_digest_basename() {
	let page = page();
	let reference = page.document_ref();
	let wire = page.canonical_cbor();
	let rendered = RenderedPlanEnvelope {
		json: b"{\"fixture\":true}".to_vec(),
		reference: Some(reference),
	};
	let artifacts = rendered.prepare(&wire).unwrap();

	let expected_name: String = reference
		.page_id()
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect();
	assert_eq!(
		artifacts.page_name().unwrap().as_bytes(),
		format!("{expected_name}.exc").as_bytes()
	);
	assert_eq!(artifacts.page(), wire);
	assert_eq!(artifacts.envelope(), b"{\"fixture\":true}\n");
}

#[test]
fn refuse_mismatched_pages_and_limits_including_the_final_line_feed() {
	let page = page();
	let reference = page.document_ref();
	let wire = page.canonical_cbor();
	let rendered = |size| RenderedPlanEnvelope {
		json: vec![b'x'; size],
		reference: Some(reference),
	};

	let accepted = rendered(MAX_PLAN_JSON_BYTES - 1).prepare(&wire).unwrap();
	assert_eq!(accepted.envelope().len(), MAX_PLAN_JSON_BYTES);
	assert!(matches!(
		rendered(MAX_PLAN_JSON_BYTES).prepare(&wire),
		Err(PlanBundleEncodingError::EnvelopeLimit)
	));

	let mut wrong = wire.to_vec();
	wrong[0] ^= 1;
	assert!(matches!(
		rendered(0).prepare(&wrong),
		Err(PlanBundleEncodingError::Page(DocumentError::DigestMismatch))
	));
	assert!(matches!(
		rendered(0).prepare(&vec![0; MAX_DOCUMENT_PAGE_BYTES + 1]),
		Err(PlanBundleEncodingError::Page(DocumentError::Size))
	));
	let unknown = RenderedPlanEnvelope {
		json: Vec::new(),
		reference: None,
	};
	assert!(matches!(
		unknown.prepare(&wire),
		Err(PlanBundleEncodingError::PageShape)
	));
}
