//! Adversarial and round-trip controls for opaque JSON Plan extensions.

use exacopy_codec::{PlanBody, PlanError, PlanExtensions, PlanJsonError, PublicPlan};

const EMPTY: &str = include_str!("../verification/plan_json/vectors/incomplete-empty.json");

fn extension(value: &str) -> String {
	EMPTY.replace("\"extensions\": {}", &format!("\"extensions\": {value}"))
}

#[test]
fn rejects_duplicate_extensions_and_nonintegral_and_out_of_range_numbers() {
	for json in [
		r#"{"org.test":null, "org.test":true}"#,
		r#"{"org.test":{"key":1, "\u006bey":2}}"#,
		r#"{"org.test":[{"key":1,"key":2}]}"#,
		r#"{"org.test":1.0}"#,
		r#"{"org.test":1e1}"#,
		r#"{"org.test":18446744073709551616}"#,
		r#"{"org.test":-18446744073709551617}"#,
		r#"[["org.test",true]]"#,
		"null",
	] {
		assert_eq!(
			PublicPlan::from_json(extension(json).as_bytes()),
			Err(PlanJsonError::Extension),
			"{json}"
		);
	}
	assert_eq!(
		PublicPlan::from_json(extension(r#"{"plain":true}"#).as_bytes()),
		Err(PlanError::Unsupported.into())
	);
}

#[test]
fn bounds_all_extension_collections_before_decoding_excess_values() {
	let root = (0..17)
		.map(|i| format!("\"org.test{i}\":null"))
		.collect::<Vec<_>>()
		.join(",");
	let nested = (0..65)
		.map(|i| format!("\"{i}\":null"))
		.collect::<Vec<_>>()
		.join(",");
	let array = vec!["null"; 4097].join(",");
	for extensions in [
		format!("{{{root}}}"),
		format!("{{\"org.test\":{{{nested}}}}}"),
		format!("{{\"org.test\":[{array}]}}"),
	] {
		assert_eq!(
			PublicPlan::from_json(extension(&extensions).as_bytes()),
			Err(PlanJsonError::Extension)
		);
	}
}

#[test]
fn deepest_canonical_extension_round_trips_and_one_more_level_is_refused() {
	let plan = PublicPlan::from_json(EMPTY.as_bytes()).expect("empty vector");
	let body = plan.body().expect("checked body");
	let mut fields = body.fields().clone();
	let mut canonical = b"\xa1\x68org.test".to_vec();
	canonical.extend([0x81; 30]);
	canonical.push(0xf6);
	fields.extensions = PlanExtensions::from_canonical_cbor(&canonical).expect("maximum depth");
	let body = PlanBody::new(fields).expect("bounded body");
	let plan = PublicPlan::from_body(&body).expect("valid JSON profile");
	let emitted = plan.to_json().expect("emit deepest extension");
	assert_eq!(
		PublicPlan::from_json(&emitted).expect("admit maximum depth"),
		plan
	);
	let deeper = format!("{{\"org.test\":{}null{}}}", "[".repeat(31), "]".repeat(31));
	assert_eq!(
		PublicPlan::from_json(extension(&deeper).as_bytes()),
		Err(PlanJsonError::Depth)
	);
}

#[test]
fn round_trips_large_escaped_extension_without_exceeding_the_json_limit() {
	let plan = PublicPlan::from_json(EMPTY.as_bytes()).expect("empty vector");
	let body = plan.body().expect("checked body");
	let mut fields = body.fields().clone();
	let mut canonical = b"\xa1\x68org.test\x7a".to_vec();
	let length = 512 * 1024_u32;
	canonical.extend(length.to_be_bytes());
	canonical.resize(
		canonical.len() + usize::try_from(length).expect("capacity"),
		0,
	);
	fields.extensions = PlanExtensions::from_canonical_cbor(&canonical).expect("bounded text");
	let body = PlanBody::new(fields).expect("bounded body");
	let plan = PublicPlan::from_body(&body).expect("valid JSON profile");
	let emitted = plan.to_json().expect("emit JSON with text escapes");
	assert!(emitted.len() > 3 * 1024 * 1024);
	assert_eq!(
		PublicPlan::from_json(&emitted).expect("admit escaped text"),
		plan
	);
}
