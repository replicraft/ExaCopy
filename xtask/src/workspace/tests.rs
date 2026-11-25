use std::collections::BTreeSet;
use std::path::Path;

use toml::Table;

use super::{
	check_dependency_groups, check_dependency_tables, check_editor_config, is_commit, is_test_only,
};
use crate::finding::Findings;

#[test]
fn accepts_functionally_grouped_root_dependencies() {
	let mut findings = Findings::default();
	check_dependency_groups(
		Path::new("Cargo.toml"),
		"[workspace.dependencies]\n# Domain identifiers\nuuid = \"1\"\n\n# Verification\nsyn = \"2\"\n[workspace.lints.rust]\nunsafe_code = \"deny\"\n",
		&mut findings,
	);
	assert!(findings.is_empty(), "{findings}");
}

#[test]
fn rejects_ungrouped_and_dotted_root_dependencies() {
	for config in [
		"[workspace.dependencies]\nserde = \"1\"",
		"[workspace.dependencies]\n#\nserde = \"1\"",
		"[workspace.dependencies.serde]\nversion = \"1\"",
	] {
		let mut findings = Findings::default();
		check_dependency_groups(Path::new("Cargo.toml"), config, &mut findings);
		assert!(!findings.is_empty(), "accepted {config}");
	}
}

#[test]
fn checks_all_member_dependency_kinds_including_target_tables() {
	let manifest = r#"
[dependencies]
serde.workspace = true
[dev-dependencies]
proptest.workspace = true
[build-dependencies]
manual = "1"
[target.'cfg(unix)'.dependencies]
renamed = { package = "renamed-actual", version = "1" }
"#
	.parse::<Table>()
	.expect("fixture is valid TOML");
	let mut findings = Findings::default();
	let path = Path::new("crates/foundation/exacopy-model/Cargo.toml");
	check_dependency_tables(path, &manifest, &mut findings);
	check_dependency_tables(
		path,
		manifest["target"]["cfg(unix)"]
			.as_table()
			.expect("valid target table"),
		&mut findings,
	);
	let output = findings.to_string();
	assert!(output.contains("build-dependencies.manual"), "{output}");
	assert!(output.contains("dependencies.renamed"), "{output}");
	assert!(!output.contains("proptest"), "{output}");
}

#[test]
fn recognizes_test_only_package_names_and_full_git_revisions() {
	assert!(is_test_only("proptest"));
	assert!(!is_test_only("exacopy-model"));
	assert!(is_commit("826136e783adda1997d1b92eecb2535e522e985a"));
	assert!(!is_commit("826136e"));
	assert!(!is_commit("826136e783Adda1997d1b92eecb2535e522e985a"));
}

#[test]
fn detects_spaces_override_in_editorconfig_rust_section() {
	let valid = "root = true\n[*]\nend_of_line = lf\ncharset = utf-8\ninsert_final_newline = true\n[*.rs]\nindent_style = tab\nindent_size = 4\n";
	let mut findings = Findings::default();
	check_editor_config(Path::new(".editorconfig"), valid, &mut findings);
	assert!(findings.is_empty(), "{findings}");
	check_editor_config(
		Path::new(".editorconfig"),
		&(valid.to_owned() + "indent_style = space\n"),
		&mut findings,
	);
	assert!(findings.to_string().contains("indent_style must be tab"));
}

#[test]
fn detects_renamed_transitive_test_packages_only_on_production_edges() {
	let fixture = crate::test_support::Fixture::new();
	fixture.write("src/lib.rs", "");
	fixture.write("wrapper/src/lib.rs", "");
	fixture.write("wrapper/proptest/src/lib.rs", "");
	fixture.write("wrapper/Cargo.toml", "[package]\nname = \"wrapper\"\nversion = \"0.1.0\"\n[dependencies]\nalias = { path = \"proptest\", package = \"proptest\" }\n");
	fixture.write(
		"wrapper/proptest/Cargo.toml",
		"[package]\nname = \"proptest\"\nversion = \"0.1.0\"\n",
	);
	for (section, expect_leak) in [
		("dependencies", true),
		("build-dependencies", true),
		("dev-dependencies", false),
	] {
		let manifest = format!(
			"[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n[workspace]\nexclude = [\"wrapper\", \"wrapper/proptest\"]\n[{section}]\nwrapper = {{ path = \"wrapper\" }}\n"
		);
		fixture.write("Cargo.toml", &manifest);
		let metadata = cargo_metadata::MetadataCommand::new()
			.current_dir(fixture.root())
			.other_options(vec!["--offline".into()])
			.exec()
			.expect("resolve Cargo's actual path-only package graph");
		let mut findings = Findings::default();
		super::check_production_graph(&metadata, &BTreeSet::new(), &mut findings);
		assert_eq!(
			findings
				.to_string()
				.contains("test-only dependency proptest"),
			expect_leak,
			"{section}: {findings}"
		);
	}
}

#[test]
fn detects_transitive_dependencies_on_matrix_classified_engineering_packages() {
	let fixture = crate::test_support::Fixture::new();
	fixture.write("src/lib.rs", "");
	fixture.write("wrapper/src/lib.rs", "");
	fixture.write("engineering/src/lib.rs", "");
	fixture.write(
		"Cargo.toml",
		"[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n[workspace]\nmembers = [\"engineering\"]\nexclude = [\"wrapper\"]\n[dependencies]\nwrapper = { path = \"wrapper\" }\n",
	);
	fixture.write(
		"wrapper/Cargo.toml",
		"[package]\nname = \"wrapper\"\nversion = \"0.1.0\"\n[dependencies]\nreusable = { path = \"../engineering\" }\n",
	);
	fixture.write(
		"engineering/Cargo.toml",
		"[package]\nname = \"reusable\"\nversion = \"0.1.0\"\n",
	);
	let metadata = cargo_metadata::MetadataCommand::new()
		.current_dir(fixture.root())
		.other_options(vec!["--offline".into()])
		.exec()
		.expect("resolve Cargo's actual path-only package graph");
	let mut findings = Findings::default();
	super::check_production_graph(
		&metadata,
		&BTreeSet::from(["reusable".into()]),
		&mut findings,
	);
	assert!(
		findings.to_string().contains("dependency reusable leaks"),
		"{findings}"
	);
}

#[test]
fn ssh_manifest_requires_portable_production_dependencies_only() {
	let fixture = crate::test_support::Fixture::new();
	fixture.write("src/lib.rs", "");
	fixture.write("helper/src/lib.rs", "");
	fixture.write(
		"helper/Cargo.toml",
		"[package]\nname = \"fixture-tool\"\nversion = \"0.1.0\"\n",
	);
	for (section, should_fail) in [
		("dependencies", false),
		("target.'cfg(unix)'.dependencies", true),
		("target.'cfg(unix)'.dev-dependencies", false),
		("build-dependencies", true),
	] {
		fixture.write(
			"Cargo.toml",
			&format!(
				"[package]\nname = \"exacopy-ssh\"\nversion = \"0.1.0\"\n[{section}]\nfixture-tool = {{ path = \"helper\" }}\n"
			),
		);
		let metadata = cargo_metadata::MetadataCommand::new()
			.current_dir(fixture.root())
			.other_options(vec!["--offline".into()])
			.exec()
			.expect("resolve Cargo's fixture metadata");
		let mut findings = Findings::default();
		super::check_caller_stream_ssh_manifest(
			metadata.root_package().expect("fixture root"),
			&mut findings,
		);
		assert_eq!(!findings.is_empty(), should_fail, "{section}: {findings}");
	}
}
