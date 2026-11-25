use cargo_metadata::{CargoOpt, Dependency, DependencyKind, MetadataCommand};

use super::{MATRIX_PATH, allowed_apfs_sibling, check};
use crate::finding::Findings;
use crate::test_support::Fixture;

const MATRIX: &str = r#"
schema_version = 1

[groups.core]
members = { domain = "crates/core/domain" }
dev.groups = ["testkit"]

[groups.contracts]
members = { capability = "crates/capability/contract" }
normal.groups = ["core"]

[groups.platform]
members = { native = "crates/platform/native" }
normal.groups = ["contracts"]

[groups.operations]
members = { workflow = "crates/operations/workflow" }
normal.groups = ["contracts"]

[groups.testkit]
members = { testkit = "crates/engineering/testkit" }
engineering = true
normal.groups = ["contracts"]
dev.groups = ["core"]
"#;

const DOMAIN: &str = "crates/core/domain";
const CAPABILITY: &str = "crates/capability/contract";
const NATIVE: &str = "crates/platform/native";
const WORKFLOW: &str = "crates/operations/workflow";
const TESTKIT: &str = "crates/engineering/testkit";

#[test]
fn accepts_valid_inversion_and_development_only_testkit() {
	let fixture = workspace();
	package(
		&fixture,
		WORKFLOW,
		"workflow",
		"[dependencies]\nport = { package = \"capability\", path = \"../../capability/contract\" }",
	);
	package(
		&fixture,
		DOMAIN,
		"domain",
		"[dev-dependencies]\ntestkit = { path = \"../../engineering/testkit\" }",
	);
	let findings = inspect(&fixture, Resolution::All);
	assert!(findings.is_empty(), "{findings}");
}

#[test]
fn rejects_members_without_their_declared_architectural_location() {
	let fixture = workspace();
	package(&fixture, DOMAIN, "unknown", "");
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(
		findings.contains("unknown has no architectural group"),
		"{findings}"
	);
	assert!(
		findings.contains("architecture member domain is absent"),
		"{findings}"
	);

	let fixture = workspace();
	package(&fixture, DOMAIN, "native", "");
	package(&fixture, NATIVE, "domain", "");
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(
		findings.contains("domain must live at crates/core/domain"),
		"{findings}"
	);
}

#[test]
fn rejects_misclassifying_engineering_directories_as_production() {
	let fixture = workspace();
	fixture.write(MATRIX_PATH, &MATRIX.replace("engineering = true", ""));
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(
		findings.contains("testkit has an engineering role and directory mismatch"),
		"{findings}"
	);
}

#[test]
fn rejects_renamed_optional_and_target_specific_edges_to_concrete_adapters() {
	let fixture = workspace();
	package(
		&fixture,
		WORKFLOW,
		"workflow",
		r#"
[features]
legacy = ["dep:adapter"]

[target.'cfg(target_os = "windows")'.dependencies]
adapter = { package = "native", path = "../../platform/native", optional = true }
"#,
	);
	let findings = inspect(&fixture, Resolution::All).to_string();
	assert!(
		findings.contains("architecture forbids normal dependency workflow -> native"),
		"{findings}"
	);
	assert!(
		findings.contains("cfg(target_os = \"windows\")"),
		"{findings}"
	);
}

#[test]
fn rejects_normal_and_build_edges_into_engineering_even_if_a_group_lists_them() {
	let fixture = workspace();
	fixture.write(
		MATRIX_PATH,
		&MATRIX.replace(
			"dev.groups = [\"testkit\"]",
			"normal.groups = [\"testkit\"]\nbuild.groups = [\"testkit\"]\ndev.groups = [\"testkit\"]",
		),
	);
	for kind in ["dependencies", "build-dependencies"] {
		package(
			&fixture,
			DOMAIN,
			"domain",
			&format!("[{kind}]\ntestkit = {{ path = \"../../engineering/testkit\" }}"),
		);
		let findings = inspect(&fixture, Resolution::All).to_string();
		assert!(
			findings.contains("dependency domain -> testkit"),
			"{kind}: {findings}"
		);
	}
}

#[test]
fn rejects_external_runtime_dependencies_in_the_pure_domain() {
	let fixture = workspace();
	package(&fixture, DOMAIN, "domain", "[dependencies]\ntokio = \"1\"");
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(
		findings.contains("architecture forbids normal dependency domain -> tokio"),
		"{findings}"
	);
}

#[test]
fn rejects_dependency_cycles_cargo_allows_between_development_edges() {
	let fixture = workspace();
	package(
		&fixture,
		DOMAIN,
		"domain",
		"[dev-dependencies]\ntestkit = { path = \"../../engineering/testkit\" }",
	);
	package(
		&fixture,
		TESTKIT,
		"testkit",
		"[dev-dependencies]\ndomain = { path = \"../../core/domain\" }",
	);
	let findings = inspect(&fixture, Resolution::All).to_string();
	assert!(
		findings.contains("workspace dependency cycle: domain -> testkit -> domain"),
		"{findings}"
	);
}

#[test]
fn transitional_edges_apply_only_to_the_listed_package_and_target() {
	let fixture = workspace();
	const EDGE: &str = "native = { path = \"../../platform/native\" }";
	fixture.write(
		MATRIX_PATH,
		&format!(
			r#"{MATRIX}
[[transitional_normal]]
from = "workflow"
to = "native"
targets = ['cfg(target_os = "linux")']
"#
		),
	);
	package(
		&fixture,
		WORKFLOW,
		"workflow",
		&format!("[target.'cfg(target_os = \"linux\")'.dependencies]\n{EDGE}"),
	);
	let findings = inspect(&fixture, Resolution::All);
	assert!(findings.is_empty(), "{findings}");
	package(
		&fixture,
		WORKFLOW,
		"workflow",
		&format!("[dependencies]\n{EDGE}"),
	);
	let findings = inspect(&fixture, Resolution::All).to_string();
	assert!(
		findings.contains("workflow -> native (all targets)"),
		"{findings}"
	);
	assert!(
		findings.contains("unused transitional allowance"),
		"{findings}"
	);
}

#[test]
fn admits_only_the_exact_macos_apfs_sibling_edge() {
	const MACOS: &str = r#"cfg(target_os = "macos")"#;
	const LINUX: &str = r#"cfg(target_os = "linux")"#;
	const PLATFORM: &str = "exacopy-platform";
	let fixture = Fixture::new();
	fixture.write("ExaCopy/Cargo.toml", "");
	fixture.write("pomologie/apfs/crates/platform/apfs-mounted/Cargo.toml", "");
	let root = fixture.root().join("ExaCopy");
	let path = fixture
		.root()
		.join("pomologie/apfs/crates/platform/apfs-mounted");
	let dependency: Dependency = serde_json::from_value(serde_json::json!({
		"name": "apfs-mounted", "req": "*", "kind": null, "optional": false,
		"uses_default_features": false, "features": [], "path": path,
	}))
	.expect("decode synthetic Cargo path dependency");
	assert!(allowed_apfs_sibling(
		&root,
		PLATFORM,
		&dependency,
		Some(MACOS)
	));
	assert!(!allowed_apfs_sibling(
		&root,
		"exacopy-transfer",
		&dependency,
		Some(MACOS)
	));
	assert!(!allowed_apfs_sibling(
		&root,
		PLATFORM,
		&dependency,
		Some(LINUX)
	));
	assert!(!allowed_apfs_sibling(&root, PLATFORM, &dependency, None));

	let mut wrong = dependency.clone();
	wrong.kind = DependencyKind::Build;
	assert!(!allowed_apfs_sibling(&root, PLATFORM, &wrong, Some(MACOS)));

	let mut wrong = dependency.clone();
	wrong.uses_default_features = true;
	assert!(!allowed_apfs_sibling(&root, PLATFORM, &wrong, Some(MACOS)));

	let mut wrong = dependency.clone();
	wrong.features.push("unchecked".into());
	assert!(!allowed_apfs_sibling(&root, PLATFORM, &wrong, Some(MACOS)));

	let mut wrong = dependency;
	wrong.path = Some(root.to_str().expect("fixture path is UTF-8").into());
	assert!(!allowed_apfs_sibling(&root, PLATFORM, &wrong, Some(MACOS)));
}

enum Resolution {
	All,
	Declarations,
}

fn workspace() -> Fixture {
	let fixture = Fixture::new();
	let members = [DOMAIN, CAPABILITY, NATIVE, WORKFLOW, TESTKIT];
	fixture.write(
		"Cargo.toml",
		&format!("[workspace]\nresolver = \"3\"\nmembers = {members:?}\n"),
	);
	fixture.write(MATRIX_PATH, MATRIX);
	for (path, name) in [
		(DOMAIN, "domain"),
		(CAPABILITY, "capability"),
		(NATIVE, "native"),
		(WORKFLOW, "workflow"),
		(TESTKIT, "testkit"),
	] {
		package(&fixture, path, name, "");
	}
	fixture
}

fn package(fixture: &Fixture, directory: &str, name: &str, body: &str) {
	fixture.write(
		&format!("{directory}/Cargo.toml"),
		&format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n{body}\n"),
	);
	fixture.write(&format!("{directory}/src/lib.rs"), "");
}

fn inspect(fixture: &Fixture, resolution: Resolution) -> Findings {
	let mut command = MetadataCommand::new();
	command
		.current_dir(fixture.root())
		.features(CargoOpt::AllFeatures)
		.other_options(vec!["--offline".into()]);
	if matches!(resolution, Resolution::Declarations) {
		command.no_deps();
	}
	let metadata = command.exec().expect("load synthetic workspace metadata");
	let mut findings = Findings::default();
	check(&metadata, &mut findings);
	findings
}
