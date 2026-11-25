//! Exercises the digest-bound Plan body and standalone extension readers.
#![no_main]
#![forbid(unsafe_code)]

use exacopy_codec::{
	DocumentPageKind, MAX_PLAN_BODY_BYTES, MAX_PLAN_IDENTITY_BYTES, PlanBody, PlanError,
	PlanExtensions,
};
use libfuzzer_sys::fuzz_target;

const PLAN_DOMAIN: &[u8] = b"ExaCopy/plan/v1\0";

fn check_body(input: &[u8]) {
	if input.len() > MAX_PLAN_BODY_BYTES {
		assert_eq!(
			PlanBody::from_canonical_cbor([0; 32], input),
			Err(PlanError::Size)
		);
		return;
	}
	// Address arbitrary original bytes, including malformed forms. This reaches
	// the field parsers rather than rejecting each mutation at the digest check.
	let digest = *blake3::Hasher::new()
		.update(PLAN_DOMAIN)
		.update(input)
		.finalize()
		.as_bytes();
	let Ok(plan) = PlanBody::from_canonical_cbor(digest, input) else {
		return;
	};

	assert_eq!(plan.canonical_cbor(), input);
	assert_eq!(plan.digest(), digest);
	assert_eq!(PlanBody::new(plan.fields().clone()), Ok(plan.clone()));

	let fields = plan.fields();
	assert_eq!(fields.plan_id.get_version_num(), 7);
	assert!(!fields.destination_root.is_nil());
	assert!(fields.source_roots.len() <= 128 && fields.source_roots.iter().all(|id| !id.is_nil()));
	assert!(fields.source_views.len() <= 128);
	assert!(fields.required_grants.len() <= 128);
	assert!(
		fields
			.required_grants
			.iter()
			.all(|grant| grant.chars().count() <= 128)
	);
	assert!(fields.entry_pages.len() <= 4096);
	let mut count = 0_u64;
	for page in &fields.entry_pages {
		assert_eq!(page.kind(), DocumentPageKind::PlanEntries);
		count = count
			.checked_add(page.item_count())
			.expect("accepted page count cannot overflow");
	}
	assert_eq!(count, fields.entry_count);
	assert!((1..=64).contains(&fields.resource_limits.io_inflight_max()));
	for instant in [Some(fields.created_at), fields.expires_at]
		.into_iter()
		.flatten()
	{
		assert!(instant.nanoseconds() < 1_000_000_000);
	}
	for view in &fields.source_views {
		assert!(!view.view_id.is_nil() && !view.root_id.is_nil() && !view.measurement_id.is_nil());
		assert!(view.provider.chars().count() <= 128);
		for instant in [Some(view.observed_at), view.stable_until]
			.into_iter()
			.flatten()
		{
			assert!(instant.nanoseconds() < 1_000_000_000);
		}
		if let Some(identity) = view.source_identity {
			for atom in [
				Some(identity.volume_id),
				Some(identity.object_id),
				identity.generation,
			]
			.into_iter()
			.flatten()
			{
				assert!((1..=MAX_PLAN_IDENTITY_BYTES).contains(&atom.len()));
			}
		}
	}
	let mut wrong_digest = digest;
	wrong_digest[0] ^= 1;
	assert_eq!(
		PlanBody::from_canonical_cbor(wrong_digest, input),
		Err(PlanError::Integrity)
	);
}

fn check_extensions(input: &[u8]) {
	if let Ok(extensions) = PlanExtensions::from_canonical_cbor(input) {
		assert!(input.len() <= MAX_PLAN_BODY_BYTES);
		assert_eq!(extensions.as_canonical_cbor(), input);
	}
}

fuzz_target!(|input: &[u8]| {
	check_body(input);
	check_extensions(input);
});
