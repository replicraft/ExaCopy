use super::{NATIVE_MANIFEST, NATIVE_PATH, add_native_fixture, inspect, workspace};
use crate::test_support::Fixture;

const TARGET: &str = "history";
const SOURCE: &str = "tests/history.rs";
const MANIFEST_PATH: &str = "exacopy-second/Cargo.toml";
const SOURCE_PATH: &str = "exacopy-second/tests/history.rs";
const MANIFEST: &str =
	"[package]\nname = \"exacopy-second\"\nversion = \"0.0.0\"\nedition = \"2024\"\n";
const BODY: &str = r#"#![cfg(target_os = "linux")]
#[test]
#[ignore = "native fixture"]
fn observes() -> Result<(), Box<dyn std::error::Error>> {
	assert!(exacopy_second::observe());
	Ok(())
}
"#;

fn manifest() -> String {
	let (header, _) = NATIVE_MANIFEST.split_once("[[case]]").unwrap();
	let header = header.replace(
		"linux-unprivileged-same-device-bind-v1",
		"linux-unprivileged-whole-ext4-sync-history-v1",
	);
	format!(
		"{header}[[case]]\nkind = \"rust-integration\"\ntest_target = \"{TARGET}\"\nselector = \"observes\"\nsource = \"{SOURCE}\"\nignored = true\n"
	)
}

fn setup() -> Fixture {
	let fixture = workspace();
	add_native_fixture(&fixture);
	fixture.write(
		"exacopy-second/src/lib.rs",
		"pub fn observe() -> bool { true }\n",
	);
	fixture.write(NATIVE_PATH, &manifest());
	fixture.write(SOURCE_PATH, BODY);
	fixture
}

#[test]
fn exact_integration_is_owned_and_adds_no_generic_gate() {
	let fixture = setup();
	let (projects, findings) = inspect(&fixture);
	assert!(findings.is_empty(), "{findings}");
	assert_eq!(projects.len(), 1);
	assert_eq!(projects[0].obligations.len(), 1);

	fixture.write(
		MANIFEST_PATH,
		&format!(
			"{MANIFEST}\n[[test]]\nname = \"{TARGET}\"\npath = \"{SOURCE}\"\nharness = true\n"
		),
	);
	let (_, findings) = inspect(&fixture);
	assert!(findings.is_empty(), "{findings}");
}

#[test]
fn integration_requires_exact_target_source_case_and_profile() {
	let fixture = setup();
	for (from, to, diagnostic) in [
		("test_target = \"history\"\n", "", "valid test_target"),
		(
			"test_target = \"history\"",
			"test_target = \"--help\"",
			"valid test_target",
		),
		(
			"test_target = \"history\"",
			"test_target = \"other\"",
			"exact owner Cargo test target",
		),
		(
			"kind = \"rust-integration\"",
			"kind = \"rust-unit\"",
			"only valid for a native Rust integration",
		),
		(
			"kind = \"rust-integration\"",
			"kind = \"command\"",
			"only valid for a native Rust integration",
		),
		(
			"kind = \"rust-integration\"",
			"kind = \"rust-integration\"\nowner = \"exacopy-first\"",
			"owner-local",
		),
		(
			"selector = \"observes\"",
			"selector = \"nested::observes\"",
			"bare, ignored",
		),
		("ignored = true", "ignored = false", "bare, ignored"),
		(SOURCE, "tests/./history.rs", "canonical under tests"),
		(SOURCE, "tests//history.rs", "canonical under tests"),
		(
			SOURCE,
			"../exacopy-first/tests/history.rs",
			"canonical under tests",
		),
		(SOURCE, "tests/missing.rs", "exact owner Cargo test target"),
		(
			"linux-unprivileged-whole-ext4-sync-history-v1",
			"linux-unprivileged-tmpfs-sync-preview-v1",
			"require the whole-ext4",
		),
	] {
		fixture.write(NATIVE_PATH, &manifest().replace(from, to));
		let (_, findings) = inspect(&fixture);
		assert!(
			findings.to_string().contains(diagnostic),
			"{from} -> {to}: {findings}"
		);
	}
}

#[test]
fn integration_refuses_custom_harness_target_alias_and_feature_gate() {
	let fixture = setup();
	fixture.write("exacopy-first/tests/history.rs", BODY);
	for (declaration, diagnostic) in [
		(
			"path = \"tests/history.rs\"\nharness = false",
			"standard libtest harness",
		),
		("path = \"tests/./history.rs\"", "canonical source"),
		(
			"path = \"../exacopy-first/tests/history.rs\"",
			"exact owner Cargo test target",
		),
		(
			"path = \"tests/history.rs\"\nrequired-features = [\"special\"]",
			"no required features",
		),
	] {
		fixture.write(
			MANIFEST_PATH,
			&format!(
				"{MANIFEST}\n[features]\nspecial = []\n\n[[test]]\nname = \"{TARGET}\"\n{declaration}\n"
			),
		);
		let (_, findings) = inspect(&fixture);
		assert!(
			findings.to_string().contains(diagnostic),
			"{declaration}: {findings}"
		);
	}
}

#[test]
fn integration_requires_substantive_top_level_linux_ignored_libtest() {
	let fixture = setup();
	for (from, to) in [
		("#![cfg(target_os = \"linux\")]", "#![cfg(unix)]"),
		(
			"#![cfg(target_os = \"linux\")]",
			"#![cfg(all(target_os = \"linux\", test))]",
		),
		(
			"#![cfg(target_os = \"linux\")]",
			"#![cfg(target_os = \"linux\")]\n#![cfg(any())]",
		),
		(
			"#![cfg(target_os = \"linux\")]",
			"#![cfg(target_os = \"linux\")]\n#![cfg_attr(test, test_runner(alternate))]",
		),
		(
			"#[test]",
			"mod nested { #[test] fn observes() {} }\n#[test]",
		),
		("#[test]", "#[test(fake)]"),
		("#[ignore = \"native fixture\"]", ""),
		("#[ignore = \"native fixture\"]", "#[ignore(false)]"),
		("#[ignore = \"native fixture\"]", "#[ignore]\n#[cfg(any())]"),
		("fn observes()", "fn observes(_: u8)"),
		("assert!(exacopy_second::observe());\n\tOk(())", ""),
	] {
		let body = if to.starts_with("mod nested") {
			format!("#![cfg(target_os = \"linux\")]\n{to}\nfn different() {{}}")
		} else {
			BODY.replace(from, to)
		};
		fixture.write(SOURCE_PATH, &body);
		let (_, findings) = inspect(&fixture);
		assert!(
			findings
				.to_string()
				.contains("substantive top-level ignored"),
			"{from} -> {to}: {findings}"
		);
	}
}

#[cfg(unix)]
#[test]
fn integration_refuses_symlink_source_even_if_metadata_lists_it() {
	let fixture = setup();
	let borrowed = fixture.write("borrowed.rs", BODY);
	let source = fixture.root().join(SOURCE_PATH);
	std::fs::remove_file(&source).unwrap();
	std::os::unix::fs::symlink(borrowed, source).unwrap();
	let (_, findings) = inspect(&fixture);
	assert!(
		findings
			.to_string()
			.contains("owned regular files without symlinks"),
		"{findings}"
	);
}
