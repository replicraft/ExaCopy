use exacopy_plan::{MAX_PLAN_JSON_BYTES, PlanJsonError, PublicPlan};
use serde_json::json;

use super::{admit, empty};

#[test]
fn dispatches_versions_before_interpreting_the_body_layout() {
	let mut document = empty();
	let body = document["body"].as_object_mut().unwrap();
	body.remove("policy");
	body.insert("future_policy".into(), json!({"actions": ["preserve"]}));
	assert_eq!(admit(&document), Err(PlanJsonError::Json));

	document["body"]["schema_version"] = json!("2.0");
	assert_eq!(admit(&document), Err(PlanJsonError::Version));

	document.as_object_mut().unwrap().remove("digest");
	assert_eq!(admit(&document), Err(PlanJsonError::Version));

	document["digest"] = json!({"algorithm": "future"});
	document["approval"] = json!(null);
	assert_eq!(admit(&document), Err(PlanJsonError::Version));
	assert_eq!(
		PublicPlan::from_json(br#"{"body":{"schema_version":"2\u002e0"}}"#),
		Err(PlanJsonError::Version)
	);
}

#[test]
fn requires_an_unambiguous_bounded_version_envelope() {
	for input in [
		r#"{"body":[{"schema_version":"2.0"}]}"#,
		r#"{"body":{"future":{"schema_version":"2.0"}}}"#,
		r#"{"body":{"schema_version":[2,0]}}"#,
		r#"{"body":{"schema_version":"2.0","schema_versi\u006fn":"2.0"}}"#,
		r#"{"body":{"schema_version":"2.0"},"b\u006fdy":{"schema_version":"2.0"}}"#,
		r#"{"body":{"schema_version":"2.0"},"digest":null,"dig\u0065st":{}}"#,
		r#"{"body":{"schema_version":"2.0"},"approval":null,"approval":{}}"#,
		r#"{"body":{"schema_version":"2.0","future":tru}}"#,
		r#"{"body":{"schema_version":"2.0"}} null"#,
	] {
		assert_eq!(
			PublicPlan::from_json(input.as_bytes()),
			Err(PlanJsonError::Json),
			"{input}"
		);
	}
	assert_eq!(
		PublicPlan::from_json(b"{\"body\":{\"schema_version\":\"2.0\",\"future\":\"\xff\"}}"),
		Err(PlanJsonError::Json)
	);

	let future = br#"{"body":{"schema_version":"2.0"}}"#;
	let mut oversized = future.to_vec();
	oversized.resize(MAX_PLAN_JSON_BYTES + 1, b' ');
	assert_eq!(PublicPlan::from_json(&oversized), Err(PlanJsonError::Size));
	let deep = format!(
		r#"{{"body":{{"schema_version":"2.0","future":{}null{}}}}}"#,
		"[".repeat(32),
		"]".repeat(32)
	);
	assert_eq!(
		PublicPlan::from_json(deep.as_bytes()),
		Err(PlanJsonError::Depth)
	);
}
