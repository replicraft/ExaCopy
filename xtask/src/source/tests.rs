use std::path::Path;

use super::check_text;
use crate::finding::Findings;

fn inspect(name: &str, source: &str) -> String {
	let mut findings = Findings::default();
	check_text(Path::new(name), source, &mut findings);
	findings.to_string()
}

#[test]
fn permits_declarations_explicit_reexports_and_kani_linkage() {
	let source = r#"//! Library boundary.
#![forbid(unsafe_code)]
mod model;
pub use model::State;
#[cfg(kani)]
#[path = "../verification/kani/mod.rs"]
mod verification;
"#;
	assert_eq!(inspect("lib.rs", source), "");
}

#[test]
fn rejects_substantive_items_regardless_of_attributes_or_layout() {
	for file in ["lib.rs", "verification/kani/mod.rs"] {
		for source in [
			"#[cfg(test)] mod tests { fn work() {} }",
			"#[cfg(any())] const VALUE: u8 = 1;",
			"include!(\"actual_implementation.rs\");",
			"mod model;\nuse model::State;",
			"pub struct State;",
			"mod a;\nimpl State {}",
		] {
			assert!(
				inspect(file, source).contains("allow only external module declarations"),
				"{file} accepted {source}"
			);
		}
	}
}

#[test]
fn permits_thin_initialization_and_delegation() {
	let source = "mod command;\nuse std::process::ExitCode;\nfn main() -> ExitCode { let args = std::env::args_os(); command::run(args) }";
	assert_eq!(inspect("main.rs", source), "");
}

#[test]
fn rejects_control_flow_helpers_hidden_macros_and_missing_delegate() {
	for (source, diagnostic) in [
		("fn helper() {} fn main() { run(); }", "define only main"),
		(
			"fn main() { for file in files { copy(file); } run(); }",
			"straight-line calls",
		),
		(
			"fn main() { run(if enabled { a } else { b }) }",
			"straight-line calls",
		),
		(
			"fn main() { run(move || process()) }",
			"straight-line calls",
		),
		("fn main() { run!(); }", "straight-line calls"),
		("fn main() {}", "must end with a call"),
		(
			"fn main() { let result = run(); result }",
			"must end with a call",
		),
		("mod helper;", "must contain one main"),
	] {
		assert!(
			inspect("main.rs", source).contains(diagnostic),
			"accepted {source}"
		);
	}
}

#[test]
fn counts_comments_blank_lines_and_nonterminated_final_line() {
	let source = "// comment\n\n".repeat(250);
	assert_eq!(inspect("src/model.rs", &source), "");
	assert!(inspect("src/model.rs", &(source + "// one more line")).contains("501 physical lines"));
}

#[test]
fn distinguishes_test_globs_from_production_globs_and_rejects_broad_suppression() {
	assert_eq!(inspect("tests/fixture.rs", "use crate::domain::*;"), "");
	assert_eq!(
		inspect("src/model.rs", "#[cfg(test)] mod tests { use super::*; }"),
		""
	);
	assert!(
		inspect("src/model.rs", "#[cfg(not(test))] use crate::{domain::*};")
			.contains("production glob import")
	);
	assert!(
		inspect(
			"src/model.rs",
			"#![allow(clippy::all, reason = \"fixture\")]\nfn parse() {}"
		)
		.contains("crate-wide lint suppression")
	);
	assert!(inspect("src/model.rs", "fn incomplete( {}").contains("invalid Rust"));
}
