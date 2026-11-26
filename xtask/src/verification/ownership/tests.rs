use std::fs;

use cargo_metadata::MetadataCommand;

use super::{INVENTORY, OWNER_INDEX};
use crate::finding::Findings;
use crate::test_support::Fixture;
use crate::verification::{Project, check};

const OWNER: &str = "exacopy-first";
const ADDITIVE: &str = "exacopy-second";
const POLICY: &str = "schema_version = 1\n[owners]\nexacopy-first = [\"rust\"]\n";
const NATIVE_POLICY: &str =
	"\n[native_fixtures]\nexacopy-second = [\"verification/demo/fixture.toml\"]\n";
const NATIVE_MANIFEST: &str = r#"
schema_version = 1
id = "demo-native"
target = "x86_64-unknown-linux-gnu"
profile = "linux-unprivileged-same-device-bind-v1"
rust_toolchain = "1.100.0"
runner = "verification/demo/run.py"
controls = "verification/demo/test_runner.py"
workflow = ".github/workflows/native.yml"
result = "result.json"

[[case]]
selector = "linux::tests::observes"
source = "src/linux/tests.rs"
ignored = true
"#;
const NATIVE_PATH: &str = "exacopy-second/verification/demo/fixture.toml";
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
	let output = findings.to_string().replace('\\', "/");
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

#[test]
fn rust_gate_features_must_be_declared_by_the_owning_package() {
	let fixture = workspace();
	fixture.write(
		"exacopy-first/Cargo.toml",
		"[package]\nname = \"exacopy-first\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[features]\nopt-in = []\n",
	);
	for (selector, expected) in [
		(r#"["opt-in"]"#, ""),
		(r#"[]"#, ""),
		(r#"["opt-in", "opt-in"]"#, "duplicate Rust gate features"),
		(r#"["missing"]"#, "undeclared Rust gate feature"),
		(r#"["opt-in,missing"]"#, "undeclared Rust gate feature"),
		(r#"["--all-features"]"#, "undeclared Rust gate feature"),
	] {
		let obligation =
			OBLIGATION.replace("rust = {", &format!("rust = {{ features = {selector},"));
		fixture.write("exacopy-first/verification/obligations.toml", &obligation);
		let (_, findings) = inspect(&fixture);
		let output = findings.to_string();
		if expected.is_empty() {
			assert!(findings.is_empty(), "{selector}: {output}");
		} else {
			assert!(output.contains(expected), "{selector}: {output}");
		}
	}
}

fn add_native_fixture(fixture: &Fixture) {
	fixture.write(INVENTORY, &format!("{POLICY}{NATIVE_POLICY}"));
	fixture.write(NATIVE_PATH, NATIVE_MANIFEST);
	fixture.write(
		"exacopy-second/src/lib.rs",
		"#[cfg(target_os = \"linux\")] mod linux;\n",
	);
	fixture.write("exacopy-second/src/linux.rs", "#[cfg(test)] mod tests;\n");
	fixture.write(
		"exacopy-second/src/linux/tests.rs",
		"#[test] #[ignore = \"native fixture\"] fn observes() { assert!(true); }\n",
	);
	fixture.write(
		"exacopy-second/verification/demo/run.py",
		"print('runner')\n",
	);
	fixture.write(
		"exacopy-second/verification/demo/test_runner.py",
		"print('controls')\n",
	);
	fixture.write(
		".github/workflows/native.yml",
		r#"env:
  EXPECTED_RUST_HOST: x86_64-unknown-linux-gnu
steps:
  - run: python3 exacopy-second/verification/demo/run.py
  - run: python3 exacopy-second/verification/demo/test_runner.py
"#,
	);
}

#[test]
fn native_only_fixture_owner_adds_no_generic_gate() {
	let fixture = workspace();
	add_native_fixture(&fixture);
	let (projects, findings) = inspect(&fixture);
	assert!(findings.is_empty(), "{findings}");
	assert_eq!(projects.len(), 1);
	assert_eq!(projects[0].package_name, OWNER);
	assert_eq!(projects[0].obligations.len(), 1);
}

#[test]
fn native_fixture_ownership_cannot_hide_unregistered_generic_ledger() {
	let fixture = workspace();
	add_native_fixture(&fixture);
	add_ledger(&fixture, ADDITIVE, "P-002");
	let (projects, findings) = inspect(&fixture);
	assert_eq!(projects.len(), 1);
	assert!(
		findings
			.to_string()
			.contains("must register its verification ownership")
	);
}

#[test]
fn native_fixture_rejects_missing_owner_and_bad_fixture_declarations() {
	let fixture = workspace();
	add_native_fixture(&fixture);
	for (old, new, expected) in [
		("ignored = true", "ignored = false", "declared ignore state"),
		(
			"linux::tests::observes",
			"linux::elsewhere::observes",
			"invalid native test selector",
		),
		(
			"x86_64-unknown-linux-gnu",
			"aarch64-apple-darwin",
			"unknown variant",
		),
		("1.100.0", "1.99.0", "does not match its profile"),
		(
			"result.json",
			"../result.json",
			"does not match its profile",
		),
		(
			"verification/demo/run.py",
			"verification/other/run.py",
			"beside the manifest",
		),
		(
			".github/workflows/native.yml",
			".github/workflows/absent.yml",
			"absent.yml",
		),
	] {
		fixture.write(NATIVE_PATH, &NATIVE_MANIFEST.replace(old, new));
		let (_, findings) = inspect(&fixture);
		assert!(findings.to_string().contains(expected), "{old}: {findings}");
	}
	fixture.write(NATIVE_PATH, NATIVE_MANIFEST);
	fixture.write(
		INVENTORY,
		&format!(
			"{POLICY}{}",
			NATIVE_POLICY.replace(ADDITIVE, "exacopy-absent")
		),
	);
	let (_, findings) = inspect(&fixture);
	assert!(
		findings
			.to_string()
			.contains("missing native fixture owner workspace member")
	);
}

#[test]
fn native_fixture_rejects_unlinked_module_and_duplicate_case() {
	let fixture = workspace();
	add_native_fixture(&fixture);
	fixture.write(
		"exacopy-second/src/linux.rs",
		"// The test source is unlinked.\n",
	);
	let (_, findings) = inspect(&fixture);
	assert!(
		findings
			.to_string()
			.contains("missing native module declaration tests")
	);
	fixture.write("exacopy-second/src/linux.rs", "#[cfg(test)] mod tests;\n");
	let case = NATIVE_MANIFEST
		.split_once("[[case]]")
		.expect("case declaration")
		.1;
	fixture.write(NATIVE_PATH, &format!("{NATIVE_MANIFEST}\n[[case]]{case}"));
	let (_, findings) = inspect(&fixture);
	assert!(
		findings
			.to_string()
			.contains("duplicate native test selector")
	);
}

#[cfg(unix)]
#[test]
fn native_fixture_rejects_symlinked_custody() {
	let fixture = workspace();
	add_native_fixture(&fixture);
	let runner = fixture
		.root()
		.join("exacopy-second/verification/demo/run.py");
	fs::remove_file(&runner).expect("remove fixture runner");
	let borrowed = fixture.write("borrowed.py", "print('external custody')\n");
	std::os::unix::fs::symlink(borrowed, runner).expect("substitute a symlink");
	let (_, findings) = inspect(&fixture);
	assert!(
		findings
			.to_string()
			.contains("owned regular files without symlinks")
	);
}

#[test]
fn native_fixture_rejects_conditional_alternate_module_sources() {
	let fixture = workspace();
	add_native_fixture(&fixture);
	fixture.write(
		"exacopy-second/src/linux.rs",
		"#[cfg_attr(test, path = \"other.rs\")] mod tests;\n",
	);
	let (_, findings) = inspect(&fixture);
	assert!(
		findings
			.to_string()
			.contains("missing native module declaration tests"),
		"{findings}"
	);
}

const SYNC_COMMAND_CASE: &str = r#"
[[case]]
kind = "command"
selector = "preview_equal"
source = "verification/demo/run.py"
ignored = false
"#;

const SYNC_UNIT_CASE: &str = r#"
[[case]]
kind = "rust-unit"
owner = "exacopy-first"
selector = "linux::tests::observes"
source = "src/linux/tests.rs"
ignored = false
"#;

fn sync_manifest(command: &str, unit: &str) -> String {
	let (header, _) = NATIVE_MANIFEST
		.split_once("[[case]]")
		.expect("manifest header");
	let header = header.replace(
		"linux-unprivileged-same-device-bind-v1",
		"linux-unprivileged-tmpfs-sync-preview-v1",
	);
	format!("{header}{command}{unit}")
}

#[test]
fn native_sync_profile_checks_cross_package_rust_and_owned_command_cases() {
	let fixture = workspace();
	add_native_fixture(&fixture);
	fixture.write(
		"exacopy-first/src/lib.rs",
		r#"pub fn observe() -> bool { true }
#[cfg(target_os = "linux")]
mod linux;
"#,
	);
	fixture.write("exacopy-first/src/linux.rs", "#[cfg(test)] mod tests;\n");
	fixture.write(
		"exacopy-first/src/linux/tests.rs",
		"#[test] fn observes() { assert!(crate::observe()); }\n",
	);

	// The legacy manifest defaults to the protected profile's local Rust case.
	let (projects, findings) = inspect(&fixture);
	assert!(findings.is_empty(), "{findings}");
	assert_eq!(projects[0].obligations.len(), 1);

	fixture.write(
		NATIVE_PATH,
		&sync_manifest(SYNC_COMMAND_CASE, SYNC_UNIT_CASE),
	);
	let (projects, findings) = inspect(&fixture);
	assert!(findings.is_empty(), "{findings}");
	assert_eq!(projects.len(), 1);
	assert_eq!(projects[0].obligations.len(), 1);

	for (old, new) in [
		(
			"verification/demo/run.py",
			"verification/demo/test_runner.py",
		),
		("ignored = false", "ignored = true"),
		("preview_equal", "linux::preview_equal"),
		(
			"kind = \"command\"",
			"kind = \"command\"\nowner = \"exacopy-second\"",
		),
	] {
		let command = SYNC_COMMAND_CASE.replace(old, new);
		fixture.write(NATIVE_PATH, &sync_manifest(&command, SYNC_UNIT_CASE));
		let (_, findings) = inspect(&fixture);
		assert!(
			findings.to_string().contains("native command case"),
			"{old}: {findings}"
		);
	}

	for (old, new, expected) in [
		(
			"exacopy-first",
			"not-in-workspace",
			"unknown workspace owner",
		),
		(
			"linux::tests::observes",
			"linux::unlinked::observes",
			"invalid native test selector",
		),
		("exacopy-first", "exacopy-second", "declared ignore state"),
	] {
		let unit = SYNC_UNIT_CASE.replace(old, new);
		fixture.write(NATIVE_PATH, &sync_manifest(SYNC_COMMAND_CASE, &unit));
		let (_, findings) = inspect(&fixture);
		assert!(findings.to_string().contains(expected), "{old}: {findings}");
	}
}

mod integration_tests;
