use std::fs;

use cargo_metadata::MetadataCommand;

use super::{INVENTORY, OWNER_INDEX};
use crate::finding::Findings;
use crate::test_support::Fixture;
use crate::verification::{Project, check};

const OWNER: &str = "exacopy-first";
const ADDITIVE: &str = "exacopy-second";
const POLICY: &str = "schema_version = 1\n[owners]\nexacopy-first = [\"rust\"]\n";
const OBLIGATION: &str = r#"
schema_version = 1
[[obligation]]
id = "P-001"
source = "src/lib.rs"
symbols = ["observe"]
assumptions = []
gates = ["rust"]
rust = { test = "observes", file = "tests/profile.rs" }
"#;

fn workspace() -> Fixture {
	let fixture = Fixture::new();
	fixture.write(
		"Cargo.toml",
		"[workspace]\nmembers = [\"exacopy-first\", \"exacopy-second\"]\nresolver = \"3\"\n",
	);
	fixture.write(INVENTORY, POLICY);
	fixture.write(OWNER_INDEX, "# Verification owners\n");
	for package in [OWNER, ADDITIVE] {
		fixture.write(
			&format!("{package}/Cargo.toml"),
			&format!("[package]\nname = \"{package}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n"),
		);
		fixture.write(
			&format!("{package}/src/lib.rs"),
			"pub fn observe() -> bool { true }\n",
		);
	}
	add_ledger(&fixture, OWNER, "P-001");
	fixture
}

fn add_ledger(fixture: &Fixture, package: &str, id: &str) {
	fixture.write(
		&format!("{package}/verification/obligations.toml"),
		&OBLIGATION.replace("P-001", id),
	);
	fixture.write(
		&format!("{package}/verification/check.sh"),
		"#!/bin/sh\ncargo test\n",
	);
	fixture.write(
		&format!("{package}/tests/profile.rs"),
		&format!(
			"#[test] fn observes() {{ assert!({}::observe()); }}\n",
			package.replace('-', "_")
		),
	);
}

fn inspect(fixture: &Fixture) -> (Vec<Project>, Findings) {
	let metadata = MetadataCommand::new()
		.current_dir(fixture.root())
		.no_deps()
		.exec()
		.expect("read isolated workspace metadata");
	let mut findings = Findings::default();
	let projects = check(&metadata, &[], &mut findings);
	(projects, findings)
}

#[test]
fn requires_registration_when_an_existing_member_adds_verification() {
	let fixture = workspace();
	let (projects, findings) = inspect(&fixture);
	assert!(findings.is_empty(), "{findings}");
	assert_eq!(projects[0].package_name, OWNER);

	add_ledger(&fixture, ADDITIVE, "P-002");
	let (_, findings) = inspect(&fixture);
	assert!(
		findings
			.to_string()
			.contains("exacopy-second must register its verification ownership"),
		"{findings}"
	);

	fixture.write(INVENTORY, &format!("{POLICY}exacopy-second = [\"rust\"]\n"));
	let (projects, findings) = inspect(&fixture);
	assert!(findings.is_empty(), "{findings}");
	assert_eq!(projects.len(), 2);
}

#[test]
fn rejects_omission_of_the_entire_registered_verification_directory() {
	let fixture = workspace();
	fs::remove_dir_all(fixture.root().join(OWNER).join("verification"))
		.expect("remove fixture verification directory");
	let (projects, findings) = inspect(&fixture);
	let output = findings.to_string();
	assert!(projects.is_empty());
	assert!(output.contains("verification/obligations.toml"), "{output}");
	assert!(output.contains("verification/check.sh"), "{output}");
}

#[test]
fn rejects_omission_of_a_registered_workspace_member() {
	let fixture = workspace();
	fixture.write(
		"Cargo.toml",
		"[workspace]\nmembers = [\"exacopy-second\"]\n",
	);
	let (_, findings) = inspect(&fixture);
	assert!(
		findings
			.to_string()
			.contains("missing verification owner workspace member exacopy-first"),
		"{findings}"
	);
}

#[test]
fn rejects_omission_of_a_minimum_gate_and_owner_documentation() {
	let fixture = workspace();
	fs::remove_file(fixture.root().join(OWNER_INDEX)).expect("remove fixture owner index");
	fixture.write(
		INVENTORY,
		&POLICY.replace("[\"rust\"]", "[\"rust\", \"tlc\"]"),
	);
	let (_, findings) = inspect(&fixture);
	let output = findings.to_string();
	assert!(output.contains(OWNER_INDEX), "{output}");
	assert!(
		output.contains("exacopy-first must declare the tlc gate"),
		"{output}"
	);
}

#[test]
fn rejects_a_missing_inventory_and_duplicate_owner_declarations() {
	let fixture = workspace();
	fs::remove_file(fixture.root().join(INVENTORY)).expect("remove fixture inventory");
	let (_, findings) = inspect(&fixture);
	assert!(findings.to_string().contains(INVENTORY), "{findings}");

	fixture.write(INVENTORY, &format!("{POLICY}exacopy-first = [\"kani\"]\n"));
	let (_, findings) = inspect(&fixture);
	assert!(findings.to_string().contains("duplicate key"), "{findings}");
}
