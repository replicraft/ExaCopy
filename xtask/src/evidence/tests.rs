use std::path::Path;

use serde_json::{Value, json};

use crate::finding::Findings;
use crate::test_support::Fixture;

use super::{file_digest, matches_digest, record};

const FIXTURE_DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn passing_json() -> Value {
	json!({
		"schema_version": 1,
		"evidence_id": "00000000-0000-4000-8000-000000000001",
		"requirement_ids": ["R-319"],
		"obligation_ids": ["P-001"],
		"kind": "test",
		"repository": "ExaCopy",
		"commit": "826136e783adda1997d1b92eecb2535e522e985a",
		"dirty": false,
		"source_digest": FIXTURE_DIGEST,
		"generated_input_digest": null,
		"lockfile_digest": FIXTURE_DIGEST,
		"tool": "cargo-nextest",
		"tool_version": "0.9.0",
		"redacted_command": ["cargo", "nextest", "run", "--locked", "-p", "exacopy-model", "--no-tests", "fail", "--", "--exact", "advances"],
		"profile": {"features": [], "target": "aarch64-apple-darwin", "os": "macOS", "filesystem": null, "hardware": null },
		"started_at": "2026-11-25T03:04:05.123+01:00",
		"duration_ms": "250",
		"seeds": [],
		"model_bounds": [],
		"assumptions": [],
		"oracle": "Advances the transaction state exactly once.",
		"outcome": "pass",
		"exit_status": 0,
		"artifact_digest": FIXTURE_DIGEST,
		"detail": {
			"theorem": null, "extraction_digest": null, "axioms_tcb": [],
			"state_count": null, "fairness": [], "trace_digest": null,
			"harness": null, "unwind_bound": null, "fuzz_target": null,
			"corpus_digest": null, "budget": null, "coverage_denominator": null,
			"mutation_denominator": null, "qualification_conditions": []
		},
		"review": { "reviewer": null, "independent": false, "justification": "Schema unit fixture." },
		"synthetic": false,
	})
}

fn validate(json: Value) -> String {
	let fixture = Fixture::new();
	let record = fixture.write("record.json", &json.to_string());
	let mut findings = Findings::default();
	if let Some(parsed) = record::read(&record, &mut findings) {
		parsed.validate(&record, &mut findings);
	}
	findings.to_string()
}

#[test]
fn accepts_complete_executed_evidence_shape_and_time_zone() {
	assert_eq!(validate(passing_json()), "");
}

#[test]
fn rejects_false_green_evidence() {
	for (key, value) in [
		("synthetic", json!(true)),
		("dirty", json!(true)),
		("exit_status", json!(1)),
		("exit_status", Value::Null),
		("started_at", Value::Null),
		("started_at", json!("2026-11-25T03:04:05.0oopsZ")),
		("started_at", json!("2026-11-25T03:04:05junk+01:00")),
		("duration_ms", json!("01")),
		("artifact_digest", json!("d41d8cd98f00b204e9800998ecf8427e")),
		("redacted_command", json!([])),
		("evidence_id", json!("../../foreign")),
		("obligation_ids", json!([])),
	] {
		let mut candidate = passing_json();
		candidate[key] = value;
		assert!(
			!validate(candidate.clone()).is_empty(),
			"accepted {key}: {}",
			candidate[key]
		);
	}
}

#[test]
fn requires_nullable_fields_to_be_present_and_rejects_unknown_fields() {
	let mut absent = passing_json();
	absent["detail"]
		.as_object_mut()
		.expect("detail is an object")
		.remove("theorem");
	assert!(validate(absent).contains("missing field `theorem`"));
	let mut unexpected = passing_json();
	unexpected["fabricated"] = json!(true);
	assert!(validate(unexpected).contains("unknown field `fabricated`"));
}

#[test]
fn binds_actual_source_and_output_bytes() {
	let fixture = Fixture::new();
	let path = fixture.write("artifact.log", "");
	assert_eq!(
		file_digest(&path).expect("fixture is readable"),
		FIXTURE_DIGEST
	);
	let mut findings = Findings::default();
	assert!(matches_digest(
		fixture.root(),
		Path::new("artifact.log"),
		Some(FIXTURE_DIGEST),
		&mut findings
	));
	fixture.write("artifact.log", "tampered test output");
	assert!(!matches_digest(
		fixture.root(),
		Path::new("artifact.log"),
		Some(FIXTURE_DIGEST),
		&mut findings
	));
	assert!(
		findings
			.to_string()
			.contains("SHA-256 digest does not match")
	);
}

#[test]
fn gate_coverage_rejects_stale_records_missing_runs_and_wrong_commands() {
	let fixture = Fixture::new();
	let root = fixture.root();
	let source = fixture.write("src/transaction.rs", "// policy fixture input\n");
	let artifact = fixture.write(
		"evidence/00000000-0000-4000-8000-000000000001.log",
		"PASS advances fixture output\n",
	);
	let revision = super::Revision {
		commit: "826136e783adda1997d1b92eecb2535e522e985a".into(),
		lockfile_digest: FIXTURE_DIGEST.into(),
	};
	let entry = toml::from_str(
		r#"
id = "P-001"
requirement_ids = ["R-319"]
source = "src/transaction.rs"
symbols = ["advance"]
assumptions = []
gates = ["rust"]
rust = { test = "advances", file = "tests/transaction.rs" }
"#,
	)
	.expect("synthetic fixture obligation parses");
	let projects = [crate::verification::Project {
		package_name: "exacopy-model".into(),
		root: root.to_path_buf(),
		obligations: vec![entry],
	}];
	let mut candidate = passing_json();
	candidate["source_digest"] = json!(file_digest(&source).expect("fixture input digest"));
	candidate["artifact_digest"] = json!(file_digest(&artifact).expect("fixture log digest"));
	let verify = |record: &Value| {
		fixture.write("evidence/record.json", &record.to_string());
		let mut findings = Findings::default();
		super::check_records(
			root,
			&root.join("evidence"),
			&projects,
			&revision,
			&mut findings,
		);
		findings.to_string()
	};
	assert_eq!(verify(&candidate), "");
	let mut stale = candidate.clone();
	stale["commit"] = json!("826136e783adda1997d1b92eecb2535e522e985b");
	let findings = verify(&stale);
	assert!(
		findings.contains("does not match the clean checkout"),
		"{findings}"
	);
	assert!(
		findings.contains("missing passing rust evidence"),
		"{findings}"
	);
	let mut blocked = candidate.clone();
	blocked["outcome"] = json!("blocked");
	assert!(verify(&blocked).contains("missing passing rust evidence"));
	let mut wrong_command = candidate;
	wrong_command["redacted_command"] = json!(["cargo", "nextest", "run", "--help", "advances"]);
	assert!(verify(&wrong_command).contains("does not bind its declared rust gate"));
}

#[test]
fn binds_optional_rust_gate_features_in_the_command_and_evidence_profile() {
	let fixture = Fixture::new();
	let entry = toml::from_str(
		r#"
id = "P-001"
source = "src/transaction.rs"
symbols = ["advance"]
assumptions = []
gates = ["rust"]
rust = { test = "advances", file = "tests/transaction.rs", features = ["experimental", "strict"] }
"#,
	)
	.expect("synthetic fixture obligation parses");
	let project = crate::verification::Project {
		package_name: "exacopy-model".into(),
		root: fixture.root().to_path_buf(),
		obligations: vec![entry],
	};
	let default_record = passing_json();
	let mut selected = default_record.clone();
	selected["profile"]["features"] = json!(["experimental", "strict"]);
	selected["redacted_command"] = json!([
		"cargo",
		"nextest",
		"run",
		"--locked",
		"-p",
		"exacopy-model",
		"--no-default-features",
		"--features",
		"experimental,strict",
		"--no-tests",
		"fail",
		"--",
		"--exact",
		"advances"
	]);
	let matches = |value: &Value| {
		let path = fixture.write("record.json", &value.to_string());
		let parsed = record::read(&path, &mut Findings::default()).expect("record parses");
		super::matches_command(
			fixture.root(),
			&project,
			&project.obligations[0],
			&parsed,
			crate::verification::Gate::Rust,
		)
	};
	assert!(matches(&selected));
	assert!(!matches(&default_record));
	let mut wrong_profile = selected.clone();
	wrong_profile["profile"]["features"] = json!(["experimental"]);
	assert!(!matches(&wrong_profile));
	let mut wrong_command = selected;
	wrong_command["redacted_command"][8] = json!("experimental");
	assert!(!matches(&wrong_command));
}

#[test]
fn binds_kani_features_in_both_executed_command_and_evidence_profile() {
	use crate::verification::{Gate, Project};

	let fixture = Fixture::new();
	let mut candidate = passing_json();
	candidate["kind"] = json!("kani");
	candidate["detail"]["harness"] = json!("kani_checks::phase::exact");
	candidate["detail"]["unwind_bound"] = json!("1");
	candidate["oracle"] = json!("Exact phase.");
	let legacy_command = json!(["verification/check.sh", "kani"]);
	let selected_command = json!([
		"verification/check.sh",
		"kani",
		"--no-default-features",
		"--features",
		"experimental,strict"
	]);
	for (declaration, command, features) in [
		("", &legacy_command, json!([])),
		("features = [], ", &legacy_command, json!([])),
		(
			r#"features = ["experimental", "strict"], "#,
			&selected_command,
			json!(["experimental", "strict"]),
		),
	] {
		let entry = toml::from_str(&format!(
			r#"
id = "P-001"
source = "src/transaction.rs"
symbols = ["advance"]
assumptions = []
gates = ["kani"]
kani = {{ {declaration}harness = "kani_checks::phase::exact", file = "verification/kani/phase.rs", unwind_bound = 1, oracle = "Exact phase." }}
"#,
		))
		.expect("synthetic fixture obligation parses");
		let project = Project {
			package_name: "exacopy-model".into(),
			root: fixture.root().to_path_buf(),
			obligations: vec![entry],
		};
		let entry = &project.obligations[0];
		let matches = |value: &Value| {
			let path = fixture.write("record.json", &value.to_string());
			let parsed = record::read(&path, &mut Findings::default()).expect("record parses");
			(
				super::matches_command(fixture.root(), &project, entry, &parsed, Gate::Kani),
				super::matches_gate(
					fixture.root(),
					&project,
					entry,
					&parsed,
					Gate::Kani,
					&mut Findings::default(),
				),
			)
		};

		candidate["redacted_command"] = (*command).clone();
		candidate["profile"]["features"] = features;
		let log = "00000000-0000-4000-8000-000000000001.log";
		if command == &selected_command {
			let profile = "EXACOPY_EVS_KANI_PROFILE_V1 --no-default-features --features experimental,strict\n";
			assert_eq!(matches(&candidate), (true, false));
			fixture.write(
				log,
				"EXACOPY_EVS_KANI_PROFILE_V1 --no-default-features --features strict\n",
			);
			assert_eq!(matches(&candidate), (true, false));
			fixture.write(log, &profile.repeat(2));
			assert_eq!(matches(&candidate), (true, false));

			let long_line = "x".repeat((profile.len() + 2) * 16_384);
			fixture.write(log, &format!("{long_line}{profile}"));
			assert_eq!(matches(&candidate), (true, false));
			fixture.write(log, &format!("{long_line}{profile}{profile}"));
			assert_eq!(matches(&candidate), (true, true));
			let unterminated = profile.trim_end_matches('\n');
			fixture.write(log, &format!("{unterminated}{long_line}\n"));
			assert_eq!(matches(&candidate), (true, false));
			fixture.write(log, &format!("{unterminated}\r\n"));
			assert_eq!(matches(&candidate), (true, true));
			fixture.write(log, &format!("{unterminated}\r"));
			assert_eq!(matches(&candidate), (true, false));
			fixture.write(log, unterminated);
			assert_eq!(matches(&candidate), (true, true));
		}
		assert_eq!(matches(&candidate), (true, true));

		let valid = candidate.clone();
		for wrong in [
			json!(["experimental"]),
			json!(["strict", "experimental"]),
			json!(["experimental", "strict", "strict"]),
		] {
			candidate["profile"]["features"] = wrong;
			assert_eq!(matches(&candidate), (true, false));
		}
		candidate = valid;
		if command == &legacy_command {
			candidate["redacted_command"] = selected_command.clone();
			assert_eq!(matches(&candidate), (false, true));
		} else {
			candidate["redacted_command"] = legacy_command.clone();
			assert_eq!(matches(&candidate), (false, true));
			candidate["redacted_command"] = selected_command.clone();
			candidate["profile"]["features"] = json!([]);
			assert_eq!(matches(&candidate), (true, false));
		}
	}
}
