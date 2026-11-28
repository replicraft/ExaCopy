use super::{OBLIGATION, inspect, workspace};

#[test]
fn kani_gate_features_must_be_declared_by_the_owning_package() {
	let fixture = workspace();
	fixture.write(
		"exacopy-first/Cargo.toml",
		"[package]\nname = \"exacopy-first\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[features]\nopt-in = []\n",
	);
	fixture.write(
		"exacopy-first/src/lib.rs",
		r#"
pub fn observe() -> bool { true }
#[cfg(kani)]
#[path = "../verification/kani/mod.rs"]
mod kani_checks;
"#,
	);
	fixture.write("exacopy-first/verification/kani/mod.rs", "mod phase;\n");
	fixture.write(
		"exacopy-first/verification/kani/phase.rs",
		"#[kani::proof]\n#[kani::unwind(1)]\nfn exact_phase() { assert!(crate::observe()); }\n",
	);
	for (selection, expected) in [
		("", ""),
		("features = [], ", ""),
		(r#"features = ["opt-in"], "#, ""),
		(
			r#"features = ["opt-in", "opt-in"], "#,
			"duplicate Kani gate features",
		),
		(
			r#"features = ["missing"], "#,
			"undeclared Kani gate feature",
		),
		(
			r#"features = ["opt-in,missing"], "#,
			"undeclared Kani gate feature",
		),
		(
			r#"features = ["--all-features"], "#,
			"undeclared Kani gate feature",
		),
	] {
		let obligation = OBLIGATION.replace(r#"gates = ["rust"]"#, r#"gates = ["rust", "kani"]"#);
		let ledger = format!(
			r#"{obligation}
kani = {{ {selection}harness = "kani_checks::phase::exact_phase", file = "verification/kani/phase.rs", unwind_bound = 1 }}
"#,
		);
		fixture.write("exacopy-first/verification/obligations.toml", &ledger);
		let (_, findings) = inspect(&fixture);
		if expected.is_empty() {
			assert!(findings.is_empty(), "{selection}: {findings}");
		} else {
			assert!(
				findings.to_string().contains(expected),
				"{selection}: {findings}"
			);
		}
	}
}
