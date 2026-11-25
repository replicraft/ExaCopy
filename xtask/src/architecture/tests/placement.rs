use super::{DOMAIN, MATRIX, MATRIX_PATH, Resolution, WORKFLOW, inspect, package, workspace};

#[test]
fn rejects_binary_target_in_a_library_even_with_an_unusual_target_path() {
	let fixture = workspace();
	package(
		&fixture,
		WORKFLOW,
		"exacopy-workflow",
		r#"
[[bin]]
name = "replicate"
path = "src/unusual.rs"
required-features = ["default-off"]

[features]
default-off = []
"#,
	);
	fixture.write(&format!("{WORKFLOW}/src/unusual.rs"), "fn main() {}");
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(
		findings.contains("product binary replicate must be owned by apps/"),
		"{findings}"
	);
}

#[test]
fn a_custom_binary_source_path_cannot_hide_application_logic() {
	let fixture = workspace();
	const APP: &str = "apps/exacopy-app";
	let manifest = std::fs::read_to_string(fixture.root().join("Cargo.toml")).unwrap();
	fixture.write(
		"Cargo.toml",
		&manifest.replace("members = [", &format!("members = [\"{APP}\", ")),
	);
	fixture.write(
		MATRIX_PATH,
		&format!(
			r#"{MATRIX}
[groups.apps]
role = "application"
members = {{ exacopy-app = "{APP}" }}
"#
		),
	);
	package(
		&fixture,
		APP,
		"exacopy-app",
		r#"
[[bin]]
name = "replicate"
path = "src/custom.rs"
"#,
	);
	fixture.write(
		&format!("{APP}/src/custom.rs"),
		"fn main() { for item in items { copy(item); } run() }",
	);
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(findings.contains("custom.rs"), "{findings}");
	assert!(findings.contains("straight-line calls"), "{findings}");
}

#[test]
fn rejects_library_target_implemented_in_another_package() {
	let fixture = workspace();
	package(
		&fixture,
		WORKFLOW,
		"exacopy-workflow",
		r#"
[lib]
path = "../../platform/exacopy-native/src/lib.rs"
"#,
	);
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(
		findings.contains("target exacopy_workflow source must belong to its package"),
		"{findings}"
	);
}

#[test]
fn rejects_unprefixed_package_names_even_when_listed_in_matrix() {
	let fixture = workspace();
	fixture.write(MATRIX_PATH, &MATRIX.replace("exacopy-domain", "domain"));
	let manifest = std::fs::read_to_string(fixture.root().join("Cargo.toml")).unwrap();
	fixture.write(
		"Cargo.toml",
		&manifest.replace(DOMAIN, "crates/foundation/domain"),
	);
	package(&fixture, "crates/foundation/domain", "domain", "");
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(
		findings.contains("package must use its fully prefixed name"),
		"{findings}"
	);
}
