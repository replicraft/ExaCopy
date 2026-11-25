#![no_main]

use exacopy_plan::{MAX_PLAN_BODY_BYTES, PlanBody, PublicPlan};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
	if let Ok(plan) = PublicPlan::from_json(input) {
		verify_round_trip(&plan);
	}

	if input.len() <= MAX_PLAN_BODY_BYTES {
		let expected = *blake3::Hasher::new()
			.update(b"ExaCopy/plan/v1\0")
			.update(input)
			.finalize()
			.as_bytes();
		if let Ok(body) = PlanBody::from_canonical_cbor(expected, input)
			&& let Ok(plan) = PublicPlan::from_body(&body)
		{
			assert_eq!(plan.canonical_cbor(), input);
			verify_round_trip(&plan);
		}
	}
});

fn verify_round_trip(plan: &PublicPlan) {
	let body = plan.body().expect("admitted plan has a checked body");
	assert_eq!(plan.canonical_cbor(), body.canonical_cbor());
	assert_eq!(plan.digest(), body.digest());

	let rendered = plan
		.to_json()
		.expect("admitted unsigned plan can be rendered");
	let restored = PublicPlan::from_json(&rendered).expect("rendered plan is accepted");
	assert_eq!(restored.canonical_cbor(), plan.canonical_cbor());
	assert_eq!(restored.digest(), plan.digest());
}
