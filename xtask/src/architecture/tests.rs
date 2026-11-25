use cargo_metadata::{CargoOpt, Dependency, DependencyKind, MetadataCommand};

use super::{MATRIX_PATH, allowed_apfs_sibling, check};
use crate::finding::Findings;
use crate::test_support::Fixture;

const MATRIX: &str = r#"
schema_version = 2

[inversion]
concrete_external = ["tokio"]

[groups.core]
members = { exacopy-domain = "crates/foundation/exacopy-domain" }
dev.groups = ["testkit"]

[groups.contracts]
members = { exacopy-capability = "crates/interfaces/exacopy-capability" }
normal.groups = ["core"]

[groups.platform]
role = "adapter"
members = { exacopy-native = "crates/platform/exacopy-native" }
normal.groups = ["contracts"]

[groups.operations]
role = "engine"
members = { exacopy-workflow = "crates/engines/exacopy-workflow" }
normal.groups = ["contracts"]

[groups.testkit]
members = { exacopy-testkit = "crates/engineering/exacopy-testkit" }
engineering = true
normal.groups = ["contracts"]
dev.groups = ["core"]
"#;

const DOMAIN: &str = "crates/foundation/exacopy-domain";
const CAPABILITY: &str = "crates/interfaces/exacopy-capability";
const NATIVE: &str = "crates/platform/exacopy-native";
const WORKFLOW: &str = "crates/engines/exacopy-workflow";
const TESTKIT: &str = "crates/engineering/exacopy-testkit";

#[test]
fn accepts_valid_inversion_and_development_only_testkit() {
	let fixture = workspace();
	package(
		&fixture,
		WORKFLOW,
		"exacopy-workflow",
		"[dependencies]\nport = { package = \"exacopy-capability\", path = \"../../interfaces/exacopy-capability\" }",
	);
	package(
		&fixture,
		DOMAIN,
		"exacopy-domain",
		"[dev-dependencies]\ntestkit = { package = \"exacopy-testkit\", path = \"../../engineering/exacopy-testkit\" }",
	);
	let findings = inspect(&fixture, Resolution::All);
	assert!(findings.is_empty(), "{findings}");
}

#[test]
fn rejects_members_without_their_declared_architectural_location() {
	let fixture = workspace();
	package(&fixture, DOMAIN, "exacopy-unknown", "");
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(
		findings.contains("exacopy-unknown has no architectural group"),
		"{findings}"
	);
	assert!(
		findings.contains("architecture member exacopy-domain is absent"),
		"{findings}"
	);

	let fixture = workspace();
	package(&fixture, DOMAIN, "exacopy-native", "");
	package(&fixture, NATIVE, "exacopy-domain", "");
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(
		findings.contains("exacopy-domain must live at crates/foundation/exacopy-domain"),
		"{findings}"
	);
}

#[test]
fn rejects_misclassifying_engineering_directories_as_production() {
	let fixture = workspace();
	fixture.write(MATRIX_PATH, &MATRIX.replace("engineering = true", ""));
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(
		findings.contains("exacopy-testkit has an engineering role and directory mismatch"),
		"{findings}"
	);
}

#[test]
fn rejects_renamed_optional_and_target_specific_edges_to_concrete_adapters() {
	let fixture = workspace();
	package(
		&fixture,
		WORKFLOW,
		"exacopy-workflow",
		r#"
[features]
legacy = ["dep:adapter"]

[target.'cfg(target_os = "windows")'.dependencies]
adapter = { package = "exacopy-native", path = "../../platform/exacopy-native", optional = true }
"#,
	);
	let findings = inspect(&fixture, Resolution::All).to_string();
	assert!(
		findings
			.contains("architecture forbids normal dependency exacopy-workflow -> exacopy-native"),
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
			"exacopy-domain",
			&format!(
				"[{kind}]\ntestkit = {{ package = \"exacopy-testkit\", path = \"../../engineering/exacopy-testkit\" }}"
			),
		);
		let findings = inspect(&fixture, Resolution::All).to_string();
		assert!(
			findings.contains("dependency exacopy-domain -> exacopy-testkit"),
			"{kind}: {findings}"
		);
	}
}

#[test]
fn rejects_external_runtime_dependencies_in_the_pure_domain() {
	let fixture = workspace();
	package(
		&fixture,
		DOMAIN,
		"exacopy-domain",
		"[dependencies]\ntokio = \"1\"",
	);
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(
		findings.contains("architecture forbids normal dependency exacopy-domain -> tokio"),
		"{findings}"
	);
}

#[test]
fn rejects_dependency_cycles_cargo_allows_between_development_edges() {
	let fixture = workspace();
	package(
		&fixture,
		DOMAIN,
		"exacopy-domain",
		"[dev-dependencies]\ntestkit = { package = \"exacopy-testkit\", path = \"../../engineering/exacopy-testkit\" }",
	);
	package(
		&fixture,
		TESTKIT,
		"exacopy-testkit",
		"[dev-dependencies]\ndomain = { package = \"exacopy-domain\", path = \"../../foundation/exacopy-domain\" }",
	);
	let findings = inspect(&fixture, Resolution::All).to_string();
	assert!(
		findings.contains(
			"workspace dependency cycle: exacopy-domain -> exacopy-testkit -> exacopy-domain"
		),
		"{findings}"
	);
}

#[test]
fn transitional_edges_apply_only_to_the_listed_package_and_target() {
	let fixture = workspace();
	const EDGE: &str =
		r#"domain = { package = "exacopy-domain", path = "../../foundation/exacopy-domain" }"#;
	fixture.write(
		MATRIX_PATH,
		&format!(
			r#"{MATRIX}
[[transitional_normal]]
from = "exacopy-workflow"
to = "exacopy-domain"
targets = ['cfg(target_os = "linux")']
"#
		),
	);
	package(
		&fixture,
		WORKFLOW,
		"exacopy-workflow",
		&format!("[target.'cfg(target_os = \"linux\")'.dependencies]\n{EDGE}"),
	);
	let findings = inspect(&fixture, Resolution::All);
	assert!(findings.is_empty(), "{findings}");
	package(
		&fixture,
		WORKFLOW,
		"exacopy-workflow",
		&format!("[dependencies]\n{EDGE}"),
	);
	let findings = inspect(&fixture, Resolution::All).to_string();
	assert!(
		findings.contains("exacopy-workflow -> exacopy-domain (all targets)"),
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
		(DOMAIN, "exacopy-domain"),
		(CAPABILITY, "exacopy-capability"),
		(NATIVE, "exacopy-native"),
		(WORKFLOW, "exacopy-workflow"),
		(TESTKIT, "exacopy-testkit"),
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

mod inversion;
mod placement;
