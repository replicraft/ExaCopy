use std::path::{Path, PathBuf};

use super::super::CaseKind;
use super::{Case, check};
use crate::finding::Findings;
use crate::test_support::Fixture;

const SOURCE: &str = "tests/unit/observations.rs";
const SELECTOR: &str = "linux::subject::tests::coverage::observes";
const DECLARATION: &str = "#[path = \"../../../tests/unit/observations.rs\"] mod coverage;\n";
const TEST: &str = "#[test] fn observes() { assert!(true); }\n";

fn fixture() -> Fixture {
	let fixture = Fixture::new();
	fixture.write(
		"src/lib.rs",
		r#"#![cfg_attr(not(target_os = "linux"), forbid(unsafe_code))]
#[cfg(target_os = "linux")]
#[forbid(unsafe_code)]
mod linux;
"#,
	);
	fixture.write("src/linux.rs", "mod subject;\n");
	fixture.write("src/linux/subject.rs", "#[cfg(test)] mod tests;\n");
	fixture.write("src/linux/subject/tests.rs", DECLARATION);
	fixture.write(SOURCE, TEST);
	fixture
}

fn inspect(fixture: &Fixture, source: &str, name: &str, ignored: bool) -> Findings {
	let case = Case {
		kind: CaseKind::RustUnit,
		owner: None,
		test_target: None,
		required_feature: None,
		selector: name.to_owned(),
		source: PathBuf::from(source),
		ignored,
	};
	let mut findings = Findings::default();
	check(
		fixture.root(),
		Path::new("fixture.toml"),
		&case,
		&mut findings,
	);
	findings
}

#[test]
fn accepts_exact_source_path_with_inherited_or_direct_test_gate() {
	let fixture = fixture();
	let findings = inspect(&fixture, SOURCE, SELECTOR, false);
	assert!(findings.is_empty(), "{findings}");

	fixture.write("src/linux/subject.rs", "mod tests;\n");
	fixture.write(
		"src/linux/subject/tests.rs",
		&format!("#[cfg(test)]\n{DECLARATION}"),
	);
	fixture.write(
		SOURCE,
		"#[test] #[ignore = \"owned fixture\"] fn observes() { assert!(true); }\n",
	);
	let findings = inspect(&fixture, SOURCE, SELECTOR, true);
	assert!(findings.is_empty(), "{findings}");
	assert!(
		inspect(&fixture, SOURCE, SELECTOR, false)
			.to_string()
			.contains("declared ignore state")
	);
}

#[test]
fn rejects_alternate_or_unlinked_module_sources() {
	for path in [
		"../../../tests/unit/substitute.rs",
		"../../../../tests/unit/observations.rs",
		"../../../tests/other/../unit/observations.rs",
		"/tests/unit/observations.rs",
	] {
		let fixture = fixture();
		fixture.write(
			"src/linux/subject/tests.rs",
			&format!("#[path = {path:?}] mod coverage;\n"),
		);
		let findings = inspect(&fixture, SOURCE, SELECTOR, false);
		assert!(
			findings
				.to_string()
				.contains("missing canonical native module declaration"),
			"{path:?} was not rejected with a module diagnostic: {findings}"
		);
	}

	let fixture = fixture();
	for source in [
		"tests/unit/../unit/observations.rs",
		"tests/observations.rs",
	] {
		let findings = inspect(&fixture, source, SELECTOR, false);
		assert!(
			findings
				.to_string()
				.contains("invalid native test selector")
		);
	}
	fixture.write(
		"src/linux/subject/tests.rs",
		&format!("#[cfg_attr(test, path = \"substitute.rs\")]\n{DECLARATION}"),
	);
	assert!(
		inspect(&fixture, SOURCE, SELECTOR, false)
			.to_string()
			.contains("missing canonical native module declaration")
	);
}

#[test]
fn rejects_disabled_modules_and_test_impostors() {
	let fixture = fixture();
	fixture.write("src/linux/subject.rs", "mod tests;\n");
	assert!(
		inspect(&fixture, SOURCE, SELECTOR, false)
			.to_string()
			.contains("requires cfg(test) custody")
	);

	fixture.write("src/linux/subject.rs", "#[cfg(any())] mod tests;\n");
	assert!(
		inspect(&fixture, SOURCE, SELECTOR, false)
			.to_string()
			.contains("missing canonical native module declaration")
	);

	fixture.write("src/linux/subject.rs", "#[cfg(test)] mod tests;\n");
	for source in [
		"// #[test] fn observes() { assert!(true); }\nfn different() {}\n",
		"#[test] fn observes() {}\n",
		"#[test] #[cfg(any())] fn observes() { assert!(true); }\n",
		"#[test] #[cfg_attr(test, ignore)] fn observes() { assert!(true); }\n",
		"#[test] #[ignore(false)] fn observes() { assert!(true); }\n",
		"#[test] fn different() { assert!(true); }\n",
	] {
		fixture.write(SOURCE, source);
		let findings = inspect(&fixture, SOURCE, SELECTOR, false);
		assert!(
			findings.to_string().contains("declared ignore state"),
			"{findings}"
		);
	}
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_test_source() {
	let fixture = fixture();
	std::fs::remove_file(fixture.root().join(SOURCE)).expect("remove the owned fixture test");
	let borrowed = fixture.write("borrowed.rs", TEST);
	std::os::unix::fs::symlink(borrowed, fixture.root().join(SOURCE))
		.expect("substitute an out-of-scope test source");
	let findings = inspect(&fixture, SOURCE, SELECTOR, false);
	assert!(
		findings
			.to_string()
			.contains("owned regular files without symlinks"),
		"{findings}"
	);
}
