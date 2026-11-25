use super::{
	CAPABILITY, DOMAIN, MATRIX, MATRIX_PATH, NATIVE, Resolution, TESTKIT, WORKFLOW, inspect,
	package, workspace,
};

#[test]
fn rejects_a_transitive_adapter_reexport_even_when_direct_edges_are_allowed() {
	let fixture = workspace();
	fixture.write(
		MATRIX_PATH,
		&MATRIX.replace(
			"normal.groups = [\"core\"]",
			"normal.groups = [\"core\", \"platform\"]",
		),
	);
	package(
		&fixture,
		CAPABILITY,
		"exacopy-capability",
		r#"
[features]
legacy = ["dep:native_adapter"]

[target.'cfg(target_os = "windows")'.dependencies]
native_adapter = { package = "exacopy-native", path = "../../platform/exacopy-native", optional = true }
"#,
	);
	package(
		&fixture,
		WORKFLOW,
		"exacopy-workflow",
		r#"[dependencies]
port = { package = "exacopy-capability", path = "../../interfaces/exacopy-capability", features = ["legacy"] }"#,
	);
	fixture.write(
		&format!("{NATIVE}/src/lib.rs"),
		"pub fn assemble() -> u8 { 4 }",
	);
	fixture.write(
		&format!("{CAPABILITY}/src/lib.rs"),
		r#"#[cfg(all(windows, feature = "legacy"))]
pub use native_adapter::assemble;"#,
	);
	fixture.write(
		&format!("{WORKFLOW}/src/lib.rs"),
		r#"#[cfg(windows)]
pub fn run() -> u8 { port::assemble() }"#,
	);

	let findings = inspect(&fixture, Resolution::All).to_string();
	assert!(
		findings.contains(
			"composition boundary forbids normal dependency exacopy-capability -> exacopy-native"
		),
		"{findings}"
	);
	assert!(
		findings.contains("exacopy-workflow -> exacopy-capability -> exacopy-native"),
		"{findings}"
	);
}

#[test]
fn application_may_compose_but_engine_cannot_depend_on_it() {
	let fixture = workspace();
	const APP: &str = "apps/exacopy-app";
	fixture.write(
		"Cargo.toml",
		&format!(
			"[workspace]\nresolver = \"3\"\nmembers = {:?}\n",
			[DOMAIN, CAPABILITY, NATIVE, WORKFLOW, TESTKIT, APP]
		),
	);
	fixture.write(
		MATRIX_PATH,
		&format!(
			r#"{MATRIX}
[groups.app]
role = "application"
members = {{ exacopy-app = "{APP}" }}
normal.groups = ["platform"]
"#
		),
	);
	package(
		&fixture,
		APP,
		"exacopy-app",
		r#"[dependencies]
native = { package = "exacopy-native", path = "../../crates/platform/exacopy-native" }"#,
	);
	fixture.write(
		&format!("{NATIVE}/src/lib.rs"),
		"pub fn assemble() -> u8 { 4 }",
	);
	fixture.write(
		&format!("{APP}/src/lib.rs"),
		"pub fn run() -> u8 { native::assemble() }",
	);
	fixture.write(
		&format!("{APP}/src/main.rs"),
		"fn main() { exacopy_app::run(); }",
	);
	let findings = inspect(&fixture, Resolution::All);
	assert!(findings.is_empty(), "{findings}");

	for kind in ["dependencies", "build-dependencies", "dev-dependencies"] {
		package(
			&fixture,
			WORKFLOW,
			"exacopy-workflow",
			&format!(
				r#"[{kind}]
composition = {{ package = "exacopy-app", path = "../../../apps/exacopy-app" }}"#
			),
		);
		let findings = inspect(&fixture, Resolution::All).to_string();
		assert!(
			findings.contains("exacopy-workflow -> exacopy-app"),
			"{kind}: {findings}"
		);
	}
}

#[test]
fn adapter_role_cannot_be_hidden_by_editing_matrix_roles() {
	let fixture = workspace();
	fixture.write(
		MATRIX_PATH,
		&MATRIX.replace("role = \"adapter\"\n", "").replace(
			"normal.groups = [\"contracts\"]",
			"normal.groups = [\"contracts\", \"platform\"]",
		),
	);
	package(
		&fixture,
		WORKFLOW,
		"exacopy-workflow",
		r#"[dependencies]
implementation = { package = "exacopy-native", path = "../../platform/exacopy-native" }"#,
	);
	let findings = inspect(&fixture, Resolution::All).to_string();
	assert!(
		findings.contains("exacopy-native has an inversion role and directory mismatch"),
		"{findings}"
	);
	assert!(
		findings.contains(
			"composition boundary forbids normal dependency exacopy-workflow -> exacopy-native"
		),
		"{findings}"
	);
}

#[test]
fn transitional_allowance_cannot_admit_a_concrete_adapter() {
	let fixture = workspace();
	fixture.write(
		MATRIX_PATH,
		&format!(
			r#"{MATRIX}
[[transitional_normal]]
from = "exacopy-workflow"
to = "exacopy-native"
targets = ['cfg(target_os = "linux")']
"#
		),
	);
	package(
		&fixture,
		WORKFLOW,
		"exacopy-workflow",
		r#"[target.'cfg(target_os = "linux")'.dependencies]
native = { package = "exacopy-native", path = "../../platform/exacopy-native" }"#,
	);
	let findings = inspect(&fixture, Resolution::All).to_string();
	assert!(
		findings.contains(
			"composition boundary forbids normal dependency exacopy-workflow -> exacopy-native"
		),
		"{findings}"
	);
}

#[test]
fn rejects_concrete_external_reexport_by_canonical_package_identity() {
	let fixture = workspace();
	fixture.write(
		MATRIX_PATH,
		&MATRIX.replace(
			"normal.groups = [\"core\"]",
			"normal.groups = [\"core\"]\nnormal.optional_external = [\"tokio\"]",
		),
	);
	package(
		&fixture,
		CAPABILITY,
		"exacopy-capability",
		r#"
[target.'cfg(target_os = "linux")'.dependencies]
runner = { package = "tokio", version = "1", optional = true }
"#,
	);
	package(
		&fixture,
		WORKFLOW,
		"exacopy-workflow",
		r#"[dependencies]
capability = { package = "exacopy-capability", path = "../../interfaces/exacopy-capability" }"#,
	);
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(
		findings.contains("exacopy-workflow -> exacopy-capability -> tokio"),
		"{findings}"
	);
}
