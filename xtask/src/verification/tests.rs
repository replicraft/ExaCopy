use std::path::Path;

use crate::finding::Findings;
use crate::test_support::Fixture;

use super::{Manifest, check_obligation, load_manifest, owned_file};

const OBLIGATION: &str = r#"
schema_version = 1
[[obligation]]
id = "P-001"
requirement_ids = ["R-319"]
source = "src/transaction.rs"
symbols = ["State::advance"]
assumptions = []
gates = ["rust", "lean", "kani", "tlc"]
rust = { test = "advances", file = "tests/transaction.rs" }
lean = { theorem = "Proofs.advances", proof = "verification/Proofs/Transaction.lean", generated = "verification/Generated/Transaction.lean" }
kani = { harness = "advance_harness", file = "verification/kani/transaction.rs", unwind_bound = 3 }
tlc = { spec = "verification/tla/Model.tla", config = "verification/tla/Model.cfg", negative_control = "verification/tla/Negative.cfg" }
"#;

fn linked_fixture() -> Fixture {
	let fixture = Fixture::new();
	fixture.write(
		"src/lib.rs",
		"#[cfg(kani)] #[path = \"../verification/kani/mod.rs\"] mod proofs;\n",
	);
	fixture.write(
		"src/transaction.rs",
		"struct State;\nimpl State { fn advance() {} }\n",
	);
	fixture.write(
		"tests/transaction.rs",
		"#[test] fn advances() { assert!(true); }\n",
	);
	fixture.write("verification/kani/mod.rs", "mod transaction;\n");
	fixture.write(
		"verification/kani/transaction.rs",
		"#[kani::proof] #[kani::unwind(3)] fn advance_harness() { assert!(true); }\n",
	);
	fixture.write(
		"verification/tla/Model.tla",
		"---- MODULE Model ----\nNext == TRUE\n====\n",
	);
	fixture.write(
		"verification/tla/Model.cfg",
		"SPECIFICATION Spec\nINVARIANT PreservesSource\n",
	);
	fixture.write(
		"verification/tla/Negative.cfg",
		"SPECIFICATION BrokenSpec\nINVARIANT PreservesSource\n",
	);
	fixture.write("verification/lakefile.toml", "name = \"ModelProofs\"\n");
	fixture.write("verification/lake-manifest.json", "{}\n");
	fixture.write("verification/lean-toolchain", "leanprover/lean4:v4.30.0\n");
	fixture.write(
		"verification/Generated/Transaction.lean",
		"def step (i : Nat) := i + 1\n",
	);
	fixture.write("verification/Proofs/Transaction.lean", "-- axiom and admit are forbidden.\n/- Nested /- sorry -/ comment -/\nnamespace Proofs\ntheorem advances : step 1 = 2 := by rfl\nend Proofs\n");
	fixture
}

fn check(fixture: &Fixture, manifest: &str) -> Findings {
	let ledger = fixture.write("verification/obligations.toml", manifest);
	let mut findings = Findings::default();
	if let Some(manifest) = load_manifest(fixture.root(), &mut findings) {
		for entry in manifest.obligations {
			check_obligation(fixture.root(), &ledger, &entry, &mut findings);
		}
	}
	findings
}

#[test]
fn accepts_owned_symbols_tests_and_crate_local_formal_assets() {
	let findings = check(&linked_fixture(), OBLIGATION);
	assert!(findings.is_empty(), "{findings}");
}

#[test]
fn rejects_missing_source_symbol_unknown_gate_and_disconnected_harness() {
	let fixture = linked_fixture();
	let symbol = check(
		&fixture,
		&OBLIGATION.replace("State::advance", "Other::advance"),
	);
	assert!(
		symbol
			.to_string()
			.contains("missing obligation source symbol Other::advance"),
		"{symbol}"
	);
	assert!(toml::from_str::<Manifest>(&OBLIGATION.replace("\"rust\"", "\"other\"")).is_err());
	fixture.write("verification/kani/mod.rs", "mod ignored;\n");
	let unlinked = check(&fixture, OBLIGATION);
	assert!(
		unlinked.to_string().contains("explicitly linked"),
		"{unlinked}"
	);
}

#[test]
fn rejects_proof_holes_malformed_unwind_and_reused_tlc_validation() {
	let fixture = linked_fixture();
	fixture.write(
		"verification/Proofs/Transaction.lean",
		"theorem advances : True := by sorry\n",
	);
	fixture.write(
		"verification/kani/transaction.rs",
		"#[kani::proof] #[kani::unwind(9)] fn advance_harness() { assert!(true); }\n",
	);
	fixture.write(
		"verification/tla/Negative.cfg",
		"SPECIFICATION Spec\nINVARIANT PreservesSource\n",
	);
	let output = check(&fixture, OBLIGATION).to_string();
	for finding in [
		"proof hole",
		"declared unwind bound",
		"control and negative control must differ",
	] {
		assert!(output.contains(finding), "missing {finding} in {output}");
	}
}

#[test]
fn rejects_misplaced_proofs_duplicate_gate_and_unowned_files() {
	let fixture = linked_fixture();
	let manifest = OBLIGATION
		.replace(
			"verification/Proofs/Transaction.lean",
			"proofs/Transaction.lean",
		)
		.replace("\"rust\",", "\"rust\", \"rust\",");
	let output = check(&fixture, &manifest).to_string();
	assert!(output.contains("under verification/Proofs/"), "{output}");
	assert!(
		output.contains("unique, nonempty verification gates"),
		"{output}"
	);
	assert!(owned_file(fixture.root(), Path::new("src/../src/transaction.rs")).is_err());
	assert!(owned_file(fixture.root(), &fixture.root().join("src/transaction.rs")).is_err());
}

#[cfg(unix)]
#[test]
fn rejects_linked_artifacts_that_escape_through_symlinks() {
	let fixture = linked_fixture();
	std::os::unix::fs::symlink(fixture.root().join("src"), fixture.root().join("foreign"))
		.expect("fixture can create symlink");
	assert!(owned_file(fixture.root(), Path::new("foreign/transaction.rs")).is_err());
}

#[test]
fn finds_property_tests_but_rejects_ignored_tests_and_macro_lookalikes() {
	let fixture = linked_fixture();
	fixture.write(
		"tests/transaction.rs",
		"proptest! { #[test] fn advances(x in any::<i32>()) { prop_assert!(x != 1); } }\n",
	);
	let findings = check(&fixture, OBLIGATION);
	assert!(findings.is_empty(), "{findings}");
	for body in [
		"#[test] #[ignore] fn advances() { assert!(true); }",
		"unknown! { #[test] fn advances(x in any::<i32>()) { prop_assert!(true); } }",
	] {
		fixture.write("tests/transaction.rs", body);
		assert!(
			check(&fixture, OBLIGATION)
				.to_string()
				.contains("expected #[test] function advances")
		);
	}
}
