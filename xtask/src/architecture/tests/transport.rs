use super::{
	CAPABILITY, DOMAIN, MATRIX, MATRIX_PATH, NATIVE, Resolution, WORKFLOW, inspect, package,
	workspace,
};
use crate::test_support::Fixture;

const SFTP: &str = "crates/adapters/exacopy-sftp-adapter";
const OTHER: &str = "crates/adapters/exacopy-other-adapter";
const SSH: &str = "crates/net/exacopy-ssh-transport";
const TUNNEL: &str = "crates/net/exacopy-tunnel-transport";
const APP: &str = "apps/exacopy-app";
const SSH_EDGE: &str =
	r#"wire = { package = "exacopy-ssh-transport", path = "../../net/exacopy-ssh-transport" }"#;

const ROLES: &str = r#"
[groups.network]
role = "transport"
members = { exacopy-ssh-transport = "crates/net/exacopy-ssh-transport", exacopy-tunnel-transport = "crates/net/exacopy-tunnel-transport" }
normal.groups = ["adapters", "network", "operations"]
build.groups = ["operations"]

[groups.adapters]
role = "adapter"
members = { exacopy-sftp-adapter = "crates/adapters/exacopy-sftp-adapter", exacopy-other-adapter = "crates/adapters/exacopy-other-adapter" }
normal.groups = ["network", "adapters"]
build.groups = ["network"]
dev.groups = ["network"]
"#;

const EXACT_EDGE: &str = r#"
[[inversion.adapter_transport]]
from = "exacopy-sftp-adapter"
to = "exacopy-ssh-transport"
"#;

fn topology() -> Fixture {
	let fixture = workspace();
	add_members(&fixture, &[SFTP, OTHER, SSH, TUNNEL]);
	fixture.write(MATRIX_PATH, &format!("{MATRIX}{ROLES}{EXACT_EDGE}"));
	package(
		&fixture,
		SFTP,
		"exacopy-sftp-adapter",
		&format!("[dependencies]\n{SSH_EDGE}"),
	);
	for (directory, name) in [
		(OTHER, "exacopy-other-adapter"),
		(SSH, "exacopy-ssh-transport"),
		(TUNNEL, "exacopy-tunnel-transport"),
	] {
		package(&fixture, directory, name, "");
	}
	fixture
}

fn add_members(fixture: &Fixture, members: &[&str]) {
	let manifest = std::fs::read_to_string(fixture.root().join("Cargo.toml"))
		.expect("read the synthetic workspace manifest");
	let entries = members
		.iter()
		.map(|member| format!("{member:?}, "))
		.collect::<String>();
	fixture.write(
		"Cargo.toml",
		&manifest.replace("members = [", &format!("members = [{entries}")),
	);
}

#[test]
fn admits_the_exact_endpoint_adapter_to_transport_and_executable_composition() {
	let fixture = topology();
	add_members(&fixture, &[APP]);
	fixture.write(
		MATRIX_PATH,
		&format!(
			r#"{MATRIX}{ROLES}{EXACT_EDGE}
[groups.app]
role = "application"
members = {{ exacopy-app = "{APP}" }}
normal.groups = ["adapters", "network"]
"#
		),
	);
	package(
		&fixture,
		SFTP,
		"exacopy-sftp-adapter",
		r#"
[features]
remote = ["dep:wire"]

[target.'cfg(target_os = "linux")'.dependencies]
wire = { package = "exacopy-ssh-transport", path = "../../net/exacopy-ssh-transport", optional = true }
"#,
	);
	package(
		&fixture,
		APP,
		"exacopy-app",
		r#"[dependencies]
sftp = { package = "exacopy-sftp-adapter", path = "../../crates/adapters/exacopy-sftp-adapter", features = ["remote"] }
tunnel = { package = "exacopy-tunnel-transport", path = "../../crates/net/exacopy-tunnel-transport" }"#,
	);
	fixture.write(&format!("{APP}/src/lib.rs"), "pub fn run() {}");
	fixture.write(
		&format!("{APP}/src/main.rs"),
		"fn main() { exacopy_app::run(); }",
	);
	fixture.write(&format!("{SSH}/src/lib.rs"), "pub fn handshake() {}");
	fixture.write(
		&format!("{SFTP}/src/lib.rs"),
		r#"#[cfg(all(target_os = "linux", feature = "remote"))]
pub fn open() { wire::handshake(); }"#,
	);
	let findings = inspect(&fixture, Resolution::All);
	assert!(findings.is_empty(), "{findings}");
}

#[test]
fn exact_transport_allowance_does_not_cover_wrong_endpoints_or_reversed_edges() {
	let cases = [
		(
			OTHER,
			"exacopy-other-adapter",
			SSH_EDGE,
			"exacopy-ssh-transport",
		),
		(
			SFTP,
			"exacopy-sftp-adapter",
			r#"wire = { package = "exacopy-tunnel-transport", path = "../../net/exacopy-tunnel-transport" }"#,
			"exacopy-tunnel-transport",
		),
		(
			SSH,
			"exacopy-ssh-transport",
			r#"adapter = { package = "exacopy-sftp-adapter", path = "../../adapters/exacopy-sftp-adapter" }"#,
			"exacopy-sftp-adapter",
		),
		(
			TUNNEL,
			"exacopy-tunnel-transport",
			SSH_EDGE,
			"exacopy-ssh-transport",
		),
		(
			OTHER,
			"exacopy-other-adapter",
			r#"adapter = { package = "exacopy-sftp-adapter", path = "../exacopy-sftp-adapter" }"#,
			"exacopy-sftp-adapter",
		),
		(NATIVE, "exacopy-native", SSH_EDGE, "exacopy-ssh-transport"),
	];
	for (directory, name, definition, target) in cases {
		let fixture = topology();
		package(
			&fixture,
			directory,
			name,
			&format!("[dependencies]\n{definition}"),
		);
		let findings = inspect(&fixture, Resolution::Declarations).to_string();
		assert!(
			findings.contains(&format!(
				"composition boundary forbids normal dependency {name} -> {target}"
			)),
			"{findings}"
		);
	}
}

#[test]
fn normal_adapter_allowance_cannot_be_used_for_build_or_dev_dependencies() {
	for (table, kind) in [("build-dependencies", "build"), ("dev-dependencies", "dev")] {
		let fixture = topology();
		package(
			&fixture,
			SFTP,
			"exacopy-sftp-adapter",
			&format!("[{table}]\n{SSH_EDGE}"),
		);
		let findings = inspect(&fixture, Resolution::Declarations).to_string();
		assert!(
			findings.contains(&format!(
				"composition boundary forbids {kind} dependency exacopy-sftp-adapter -> exacopy-ssh-transport"
			)),
			"{findings}"
		);
		assert!(
			findings.contains(
				"unused adapter-to-transport allowance exacopy-sftp-adapter -> exacopy-ssh-transport"
			),
			"{findings}"
		);
	}
}

#[test]
fn exact_pairs_are_validated_against_the_workspace_and_cannot_be_duplicated() {
	let fixture = topology();
	fixture.write(
		MATRIX_PATH,
		&format!(
			r#"{MATRIX}{ROLES}{EXACT_EDGE}{EXACT_EDGE}
[[inversion.adapter_transport]]
from = "exacopy-native"
to = "exacopy-ssh-transport"
[[inversion.adapter_transport]]
from = "exacopy-sftp-adapter"
to = "exacopy-native"
[[inversion.adapter_transport]]
from = "exacopy-sftp-adapter"
to = "unregistered-transport"
"#
		),
	);
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	for invalid in [
		"invalid adapter-to-transport allowance exacopy-native -> exacopy-ssh-transport",
		"invalid adapter-to-transport allowance exacopy-sftp-adapter -> exacopy-native",
		"invalid adapter-to-transport allowance exacopy-sftp-adapter -> unregistered-transport",
		"duplicate adapter-to-transport allowance exacopy-sftp-adapter -> exacopy-ssh-transport",
	] {
		assert!(findings.contains(invalid), "{findings}");
	}
}

#[test]
fn a_transitional_exception_cannot_replace_a_normal_composition_allowance() {
	let fixture = topology();
	let matrix = ROLES.replace(
		"normal.groups = [\"network\", \"adapters\"]",
		"normal.groups = [\"adapters\"]",
	);
	fixture.write(
		MATRIX_PATH,
		&format!(
			r#"{MATRIX}{matrix}{EXACT_EDGE}
[[transitional_normal]]
from = "exacopy-sftp-adapter"
to = "exacopy-ssh-transport"
targets = ['cfg(target_os = "linux")']
"#
		),
	);
	package(
		&fixture,
		SFTP,
		"exacopy-sftp-adapter",
		&format!("[target.'cfg(target_os = \"linux\")'.dependencies]\n{SSH_EDGE}"),
	);
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(
		findings.contains(
			"architecture forbids normal dependency exacopy-sftp-adapter -> exacopy-ssh-transport"
		),
		"{findings}"
	);
	assert!(
		findings.contains(
			"unused transitional allowance exacopy-sftp-adapter -> exacopy-ssh-transport"
		),
		"{findings}"
	);
}

#[test]
fn engine_cannot_reach_a_transport_through_endpoint_and_shared_helper() {
	let fixture = topology();
	let matrix = MATRIX.replace(
		"members = { exacopy-domain = \"crates/foundation/exacopy-domain\" }",
		"members = { exacopy-domain = \"crates/foundation/exacopy-domain\" }\nnormal.groups = [\"network\"]",
	);
	fixture.write(MATRIX_PATH, &format!("{matrix}{ROLES}{EXACT_EDGE}"));
	package(
		&fixture,
		WORKFLOW,
		"exacopy-workflow",
		r#"[dependencies]
port = { package = "exacopy-capability", path = "../../interfaces/exacopy-capability" }"#,
	);
	package(
		&fixture,
		CAPABILITY,
		"exacopy-capability",
		r#"[dependencies]
shared = { package = "exacopy-domain", path = "../../foundation/exacopy-domain" }"#,
	);
	package(
		&fixture,
		DOMAIN,
		"exacopy-domain",
		&format!("[target.'cfg(target_os = \"windows\")'.dependencies]\n{SSH_EDGE}"),
	);
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(
		findings.contains(
			"composition boundary forbids normal dependency exacopy-domain -> exacopy-ssh-transport"
		),
		"{findings}"
	);
	assert!(
		findings.contains(
			"exacopy-workflow -> exacopy-capability -> exacopy-domain -> exacopy-ssh-transport"
		),
		"{findings}"
	);
}

#[test]
fn transport_role_is_derived_and_transport_cannot_import_production_workflow() {
	let fixture = topology();
	let roles = ROLES.replace("role = \"transport\"", "role = \"adapter\"");
	fixture.write(MATRIX_PATH, &format!("{MATRIX}{roles}{EXACT_EDGE}"));
	package(
		&fixture,
		SSH,
		"exacopy-ssh-transport",
		r#"[build-dependencies]
workflow = { package = "exacopy-workflow", path = "../../engines/exacopy-workflow" }"#,
	);
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(
		findings.contains("exacopy-ssh-transport has an inversion role and directory mismatch"),
		"{findings}"
	);
	assert!(
		findings.contains(
			"composition boundary forbids build dependency exacopy-ssh-transport -> exacopy-workflow"
		),
		"{findings}"
	);
}

#[test]
fn engine_dev_edge_does_not_bring_a_transport_into_its_test_closure() {
	let fixture = topology();
	let matrix = MATRIX.replace(
		"members = { exacopy-workflow = \"crates/engines/exacopy-workflow\" }",
		"members = { exacopy-workflow = \"crates/engines/exacopy-workflow\" }\ndev.groups = [\"network\"]",
	);
	fixture.write(MATRIX_PATH, &format!("{matrix}{ROLES}{EXACT_EDGE}"));
	package(
		&fixture,
		WORKFLOW,
		"exacopy-workflow",
		&format!("[dev-dependencies]\n{SSH_EDGE}"),
	);
	let findings = inspect(&fixture, Resolution::Declarations).to_string();
	assert!(
		findings.contains(
			"composition boundary forbids dev dependency exacopy-workflow -> exacopy-ssh-transport"
		),
		"{findings}"
	);
	assert!(findings.contains("engine dependency reaches concrete implementation or composition: exacopy-workflow -> exacopy-ssh-transport"), "{findings}");
}
