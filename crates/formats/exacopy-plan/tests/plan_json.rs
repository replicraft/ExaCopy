//! Interoperability and refusal tests for the unsigned public Plan JSON projection.

use exacopy_plan::{
	MAX_PLAN_JSON_BYTES, PlanBody, PlanError, PlanJsonError, PublicPlan, UnixTimestamp,
};
use serde_json::{Value, json};

#[path = "plan_json/version.rs"]
mod version;

const COMPLETE_JSON: &[u8] =
	include_bytes!("../verification/plan_json/vectors/complete-protected.json");
const COMPLETE_CBOR: &[u8] =
	include_bytes!("../verification/plan_json/vectors/complete-protected.body.cbor");
const EMPTY_JSON: &[u8] = include_bytes!("../verification/plan_json/vectors/incomplete-empty.json");
const EMPTY_CBOR: &[u8] =
	include_bytes!("../verification/plan_json/vectors/incomplete-empty.body.cbor");

fn empty() -> Value {
	serde_json::from_slice(EMPTY_JSON).expect("independent empty vector is valid JSON")
}

fn admit(value: &Value) -> Result<PublicPlan, PlanJsonError> {
	PublicPlan::from_json(&serde_json::to_vec(value).expect("write fixture"))
}

fn text(input: &[u8]) -> &str {
	std::str::from_utf8(input).expect("UTF-8 fixture")
}

#[test]
fn matches_independent_json_cbor_vectors_and_returns_a_checked_borrowed_body() {
	for (json, cbor) in [(COMPLETE_JSON, COMPLETE_CBOR), (EMPTY_JSON, EMPTY_CBOR)] {
		let plan = PublicPlan::from_json(json).expect("admit independent JSON vector");
		assert_eq!(plan.canonical_cbor(), cbor);
		let body = plan.body().expect("borrows revalidated canonical bytes");
		assert_eq!(plan.digest(), body.digest());
		assert_eq!(body.canonical_cbor(), cbor);

		let encoded = plan.to_json().expect("emit unsigned envelope");
		assert_eq!(
			PublicPlan::from_json(&encoded).expect("round trip JSON"),
			plan
		);
		assert_eq!(
			PublicPlan::from_body(&body).expect("construct from checked body"),
			plan
		);
	}
	let complete = PublicPlan::from_json(COMPLETE_JSON).expect("complete vector");
	let body = complete.body().expect("checked body");
	let identity = body.fields().source_views[0]
		.source_identity
		.expect("fixture identity");
	assert_eq!(identity.volume_id, b"v\0");
	assert_eq!(identity.object_id, b"\xffobj");
	assert_eq!(identity.generation, Some(&b"g"[..]));
	assert_eq!(body.fields().entry_pages.len(), 2);
	assert_eq!(
		body.fields().resource_limits.buffer_budget_bytes(),
		u64::MAX
	);
	let output = complete.to_json().expect("emit complete vector");
	let rendered = text(&output);
	assert!(rendered.contains("2023-11-14T22:13:20.123456789Z"));
	assert!(rendered.contains("-18446744073709551616"));
	assert!(rendered.contains("18446744073709551615"));
	assert!(!rendered.contains("\"approval\":"));
}

#[test]
fn refuses_attached_approval_even_when_null_and_accepts_an_unsigned_approval_requirement() {
	for attachment in [json!(null), json!({}), json!([1]), json!(true)] {
		let mut document = empty();
		document["approval"] = attachment;
		assert_eq!(admit(&document), Err(PlanJsonError::Approval));
	}
	let plan = PublicPlan::from_json(COMPLETE_JSON).expect("admit unsigned plan with requirement");
	assert!(
		plan.body()
			.expect("checked body")
			.fields()
			.approval_required
	);
}

#[test]
fn refuses_tampered_body_digest_and_wrong_lexical_scalar_forms() {
	let mut modified = empty();
	modified["body"]["complete"] = json!(true);
	assert_eq!(admit(&modified), Err(PlanError::Integrity.into()));
	modified["digest"] = json!("0".repeat(64));
	assert_eq!(admit(&modified), Err(PlanError::Integrity.into()));

	for digest in ["0", &"A".repeat(64), &"g".repeat(64)] {
		let mut document = empty();
		document["digest"] = json!(digest);
		assert_eq!(admit(&document), Err(PlanJsonError::Digest));
	}

	for count in ["", "01", "-0", "1e0", "+1", "18446744073709551616"] {
		let mut document = empty();
		document["body"]["entry_count"] = json!(count);
		assert_eq!(admit(&document), Err(PlanJsonError::Integer), "{count:?}");
	}

	let mut document = empty();
	document["body"]["destination_root"] = json!("18291f52801548ffaf49546767ec49cd");
	assert_eq!(admit(&document), Err(PlanJsonError::Identifier));

	document = empty();
	document["body"]["schema_version"] = json!("2.0");
	assert_eq!(admit(&document), Err(PlanJsonError::Version));

	document = empty();
	document["body"]["policy"]["follow_symlinks"] = json!(true);
	assert_eq!(admit(&document), Err(PlanJsonError::Unsupported));
}

#[test]
fn all_structs_are_map_only_and_reject_missing_duplicate_and_unknown_fields() {
	let complete = PublicPlan::from_json(COMPLETE_JSON).expect("admit complete JSON vector");
	assert_eq!(complete.canonical_cbor(), COMPLETE_CBOR);

	// Preserve the complete body bytes so either member alone would be valid.
	let (prefix, body_and_end) = text(COMPLETE_JSON)
		.split_once("\"body\": ")
		.expect("complete fixture has a body");
	let body = body_and_end
		.trim_end()
		.strip_suffix('}')
		.expect("complete fixture ends with the envelope delimiter")
		.trim_end();
	let duplicate_body = format!("{prefix}\"body\": {body}, \"body\": {body}}}");
	assert_eq!(
		PublicPlan::from_json(duplicate_body.as_bytes()),
		Err(PlanJsonError::Json)
	);

	// The positional struct-array alternative would otherwise be accepted by Serde.
	let body = empty()["body"].clone();
	let digest = empty()["digest"].clone();
	assert_eq!(admit(&json!([body, digest])), Err(PlanJsonError::Json));

	for key in ["body", "digest"] {
		let mut document = empty();
		document.as_object_mut().expect("envelope").remove(key);
		assert_eq!(admit(&document), Err(PlanJsonError::Json), "{key}");
	}

	for key in ["expires_at", "policy", "source_views", "extensions"] {
		let mut document = empty();
		document["body"].as_object_mut().expect("body").remove(key);
		assert_eq!(admit(&document), Err(PlanJsonError::Json), "{key}");
	}
	for (key, replacement) in [
		("resource_limits", json!(["0", 1])),
		("policy", json!(["preserve", "error", "blake3_readback"])),
		("entry_pages", json!([["digest", "plan_entries", "1", "0"]])),
		("source_views", json!([["view", "root"]])),
	] {
		let mut document = empty();
		document["body"][key] = replacement;
		assert_eq!(admit(&document), Err(PlanJsonError::Json), "{key}");
	}

	for (search, replacement) in [
		("\"body\": {", "\"body\": {\"other\": false,"),
		("\"policy\": {", "\"policy\": {\"other\": false,"),
		("\"policy\": {", "\"policy\": {\"conflict\": \"error\","),
		(
			"\"resource_limits\": {",
			"\"resource_limits\": {\"io_inflight_max\": 1,",
		),
	] {
		let modified = text(EMPTY_JSON).replacen(search, replacement, 1);
		assert_ne!(modified, text(EMPTY_JSON), "{search}");
		assert_eq!(
			PublicPlan::from_json(modified.as_bytes()),
			Err(PlanJsonError::Json)
		);
	}

	for (search, replacement) in [
		(
			"\"source_identity\": {",
			"\"source_identity\": {\"platform\": \"macos\",",
		),
		(
			"\"source_identity\": {",
			"\"source_identity\": {\"other\": null,",
		),
		("\"generation_base64\": \"Zw==\"", "\"unused\": null"),
	] {
		let modified = text(COMPLETE_JSON).replacen(search, replacement, 1);
		assert_ne!(modified, text(COMPLETE_JSON), "{search}");
		assert_eq!(
			PublicPlan::from_json(modified.as_bytes()),
			Err(PlanJsonError::Json)
		);
	}
}

#[test]
fn validates_lexical_dates_before_calendar_parsing_and_normalizes_utc() {
	for timestamp in [
		"1970-01-01t00:00:00z",
		"1970-01-01T00:00:00.0Z",
		"1970-01-01T00:00:00.000000000Z",
		"1969-12-31T23:30:00-00:30",
		"1970-01-01T05:30:00+05:30",
	] {
		let mut document = empty();
		document["body"]["created_at"] = json!(timestamp);
		let plan = admit(&document).expect(timestamp);
		assert_eq!(plan.canonical_cbor(), EMPTY_CBOR);
		assert!(text(&plan.to_json().expect("encode UTC")).contains("1970-01-01T00:00:00Z"));
	}

	for timestamp in [
		"1970-01-01 00:00:00Z",
		"1970-01-01T00:00:00",
		"1970-01-01T00:00:00Z ",
		" 1970-01-01T00:00:00Z",
		"1970-01-01T00:00:00+0000",
		"1970-01-01T00:00:00+00:00:00",
		"1970-01-01T00:00:00−00:00",
		"1970-01-01T00:00:00.0000000000Z",
		"1970-01-01T00:00:00.Z",
		"1970-01-01T00:00:00,0Z",
		"1970-02-29T00:00:00Z",
		"1970-01-01T24:00:00Z",
		"1970-01-01T00:00:00+24:00",
		"1970-01-01T00:00:00+00:60",
		"2016-12-31T23:59:60Z",
		"2016-12-31T23:59:60.1Z",
		"0000-01-01T00:00:00+00:01",
		"9999-12-31T23:59:59-00:01",
	] {
		let mut document = empty();
		document["body"]["created_at"] = json!(timestamp);
		assert_eq!(
			admit(&document),
			Err(PlanJsonError::Timestamp),
			"{timestamp}"
		);
	}
}

#[test]
fn normalizes_independent_timestamp_vectors_without_changing_canonical_plan() {
	#[derive(serde::Deserialize)]
	struct TimestampVector {
		input: String,
		seconds: i64,
		nanoseconds: u32,
		canonical: String,
	}
	let vectors: Vec<TimestampVector> = serde_json::from_slice(include_bytes!(
		"../verification/plan_json/vectors/timestamps.json"
	))
	.expect("independent timestamp vectors");
	let template = PublicPlan::from_json(EMPTY_JSON).expect("empty plan");
	let template_body = template.body().expect("checked body");
	for vector in vectors {
		let mut fields = template_body.fields().clone();
		fields.created_at = UnixTimestamp::new(vector.seconds, vector.nanoseconds)
			.expect("independent normalized timestamp");
		let body = PlanBody::new(fields).expect("checked timestamp body");
		let expected = PublicPlan::from_body(&body).expect("render timestamp");
		let mut document: Value =
			serde_json::from_slice(&expected.to_json().expect("public JSON")).expect("JSON fields");
		assert_eq!(document["body"]["created_at"], vector.canonical);
		document["body"]["created_at"] = json!(vector.input);
		assert_eq!(admit(&document).expect("parse timestamp"), expected);
	}
}

#[test]
fn converts_canonical_four_digit_year_boundaries_and_refuses_binary_only_dates() {
	let plan = PublicPlan::from_json(EMPTY_JSON).expect("empty vector");
	let body = plan.body().expect("checked body");
	for (seconds, date) in [
		(-62_167_219_200, "0000-01-01T00:00:00Z"),
		(253_402_300_799, "9999-12-31T23:59:59Z"),
	] {
		let mut fields = body.fields().clone();
		fields.created_at = UnixTimestamp::new(seconds, 0).expect("whole seconds");
		let body = PlanBody::new(fields).expect("valid plan body");
		let plan = PublicPlan::from_body(&body).expect("valid four-digit year");
		let emitted = plan.to_json().expect("emit timestamp");
		assert!(text(&emitted).contains(date));
		assert_eq!(
			PublicPlan::from_json(&emitted).expect("round-trip boundary"),
			plan
		);
	}

	for seconds in [i64::MIN, -62_167_219_201, 253_402_300_800, i64::MAX] {
		let mut fields = body.fields().clone();
		fields.created_at = UnixTimestamp::new(seconds, 0).expect("whole seconds");
		let binary = PlanBody::new(fields).expect("valid binary timestamp");
		assert_eq!(
			PublicPlan::from_body(&binary),
			Err(PlanJsonError::Timestamp)
		);
	}
}

#[test]
fn validates_identity_b64_before_using_borrowed_identity_atoms() {
	for invalid in ["", "dg", "dg=", "dh==", "d_==", &"A".repeat(348)] {
		let modified = text(COMPLETE_JSON).replacen("dgA=", invalid, 1);
		assert_ne!(modified, text(COMPLETE_JSON));
		assert_eq!(
			PublicPlan::from_json(modified.as_bytes()),
			Err(PlanJsonError::Base64),
			"{invalid}"
		);
	}
	let plan = PublicPlan::from_json(COMPLETE_JSON).expect("complete vector");
	let body = plan.body().expect("checked body");
	let mut fields = body.fields().clone();
	let max = [0xff; exacopy_plan::MAX_PLAN_IDENTITY_BYTES];
	let identity = fields.source_views[0]
		.source_identity
		.as_mut()
		.expect("identity");
	identity.volume_id = &max;
	let binary = PlanBody::new(fields).expect("maximum length identity");
	let plan = PublicPlan::from_body(&binary).expect("represent identity");
	assert_eq!(
		PublicPlan::from_json(&plan.to_json().expect("emit")).expect("round trip"),
		plan
	);
}

#[test]
fn rejects_recursion_and_oversized_body_collections_before_element_construction() {
	let too_large = vec![b' '; MAX_PLAN_JSON_BYTES + 1];
	assert_eq!(PublicPlan::from_json(&too_large), Err(PlanJsonError::Size));

	let mut document = empty();
	document["body"]["source_roots"] = json!(vec!["ffeeddcc-bbaa-4988-8776-554433221100"; 129]);
	assert_eq!(admit(&document), Err(PlanJsonError::Json));

	let mut document = empty();
	document["body"]["required_grants"] = json!(vec!["read"; 129]);
	assert_eq!(admit(&document), Err(PlanJsonError::Json));
	let mut document = empty();
	document["body"]["source_views"] = json!(vec![
		json!({
			"view_id": "e57d5e90-ad55-446e-a983-4cc60a94290a",
			"root_id": "ffeeddcc-bbaa-4988-8776-554433221100",
			"consistency": "live_observed",
			"provider": "test",
			"measurement_id": "00112233-4455-4677-8899-aabbccddeeff",
			"source_identity": null,
			"observed_at": "1970-01-01T00:00:00Z",
			"snapshot_token_digest": null,
			"stable_until": null
		});
		129
	]);
	assert_eq!(admit(&document), Err(PlanJsonError::Json));
	let mut document = empty();
	document["body"]["entry_pages"] = json!(vec![
		json!({"page_id":"0".repeat(64),"page_kind":"plan_entries","encoded_bytes":"1","entry_count":"0"});
		4097
	]);
	assert_eq!(admit(&document), Err(PlanJsonError::Json));
}

#[test]
fn resource_io_counts_match_the_same_binary_body_for_equivalent_decimal_spellings() {
	use exacopy_plan::PlanResourceLimits;

	let plan = PublicPlan::from_json(EMPTY_JSON).expect("independent empty vector");
	let baseline = plan.body().expect("checked body");
	for count in 1..=64 {
		let mut fields = baseline.fields().clone();
		fields.resource_limits = PlanResourceLimits::new(0, count).expect("valid count");
		let body = PlanBody::new(fields).expect("canonical integer body");
		let envelope = PublicPlan::from_body(&body).expect("representable body");
		let canonical = envelope.to_json().expect("canonical output");
		let integer = format!("\"io_inflight_max\":{count}");
		assert!(text(&canonical).contains(&integer));
		let delayed_exponent = format!("{count}.{}e+{}0", "0".repeat(500), "0".repeat(500));
		let compensating_scale = format!(
			"0.{}{count}e{}",
			"0".repeat(500),
			500 + count.to_string().len()
		);
		for spelling in [
			format!("{count}.0"),
			format!("{count}e0"),
			format!("0.{count}0e{}", count.to_string().len()),
			format!("{count}00e-2"),
			delayed_exponent,
			compensating_scale,
		] {
			let variant =
				text(&canonical).replacen(&integer, &format!("\"io_inflight_max\":{spelling}"), 1);
			let decoded = PublicPlan::from_json(variant.as_bytes()).expect(&spelling);
			assert_eq!(
				decoded.canonical_cbor(),
				body.canonical_cbor(),
				"{spelling}"
			);
			assert_eq!(decoded.to_json().expect("normalized output"), canonical);
		}
	}
}

#[test]
fn resource_io_count_normalizes_exact_scale_and_refuses_rounding_or_overflow() {
	use exacopy_plan::PlanResourceLimits;

	let plan = PublicPlan::from_json(EMPTY_JSON).expect("independent empty vector");
	let body = plan.body().expect("checked body");
	let mut fields = body.fields().clone();
	fields.resource_limits = PlanResourceLimits::new(0, 64).expect("maximum count");
	let body = PlanBody::new(fields).expect("canonical maximum body");
	let max = PublicPlan::from_body(&body).expect("representable body");
	let max_json = max.to_json().expect("render maximum count");
	for spelling in ["6.4e1", "640e-1", "6.400000000000000000000000000000e1"] {
		let modified = text(&max_json).replacen(
			"\"io_inflight_max\":64",
			&format!("\"io_inflight_max\":{spelling}"),
			1,
		);
		assert_eq!(PublicPlan::from_json(modified.as_bytes()), Ok(max.clone()));
	}

	let oversized_exponent = format!("1e+{}", "9".repeat(500));
	let huge_fraction = format!("1.{}1", "0".repeat(500));
	for spelling in [
		"0",
		"-0",
		"-1.0",
		"65",
		"6.5e1",
		"1.0000000000000000001",
		"0.9999999999999999999",
		"0.1e0",
		"1e-100",
		"1e+100",
		"1e-9999999999999999999999999",
		&oversized_exponent,
		&huge_fraction,
		"\"1\"",
		"true",
		"null",
	] {
		let modified = text(EMPTY_JSON).replacen(
			"\"io_inflight_max\": 1",
			&format!("\"io_inflight_max\": {spelling}"),
			1,
		);
		assert_ne!(modified, text(EMPTY_JSON));
		assert!(
			PublicPlan::from_json(modified.as_bytes()).is_err(),
			"{spelling}"
		);
	}
}
