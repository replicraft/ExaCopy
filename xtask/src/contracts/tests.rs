use std::path::Path;

use super::{Contract, INVENTORY, check, check_record, check_text};
use crate::finding::Findings;
use crate::test_support::Fixture;

const CURRENT: &str = include_str!("../../../docs/specs/contracts/versions.toml");
const DIFF: &str = r#"
id = "exacopy.cli.diff"
kind = "cli_output"
status = "implemented"
version = "1.0"
owner = "crates/clients/cli/src/report.rs"
"#;
const FRAME: &str = r#"
id = "local-journal-frame"
kind = "transfer_journal"
status = "implemented_private"
version = "1"
owner = "crates/storage/journal/src/frame.rs"
magic = "EXAJNL01"
"#;
const PLAN: &str = r#"
id = "darwin-managed-apfs-copy-plan"
kind = "transfer_journal"
status = "implemented_private"
version = "2.0"
required_features = 1
owner = "crates/operations/transfer/src/macos/plan/wire.rs"
"#;

fn root() -> &'static Path {
	Path::new(env!("CARGO_MANIFEST_DIR"))
		.parent()
		.expect("xtask belongs to the workspace")
}

#[test]
fn repository_inventory_matches_all_implementation_anchors() {
	let mut findings = Findings::default();
	check(root(), &mut findings);
	assert!(findings.is_empty(), "{findings}");
}

#[test]
fn rejects_invalid_inventory_schema_or_coverage() {
	for (from, to, expected) in [
		(
			"inventory_version = 1",
			"inventory_version = 2",
			"unsupported contract inventory version",
		),
		(
			"inventory_version = 1",
			"inventory_version = 1\nunreviewed = true",
			"unknown field",
		),
		("id = \"ipc\"", "id = \"mcp\"", "duplicate contract"),
		("id = \"ipc\"", "id = \"unlisted\"", "ipc: missing contract"),
		(
			"id = \"ipc\"",
			"id = \"unlisted\"",
			"unlisted: unknown contract",
		),
		(
			"status = \"planned\"",
			"status = \"planned\"\nversion = \"1.0\"",
			"unavailable contract has implementation markers",
		),
		(
			"status = \"planned\"",
			"status = \"implemented\"",
			"expected kind Configuration and status Planned",
		),
		(
			"kind = \"cli_output\"",
			"kind = \"transfer_journal\"",
			"expected kind CliOutput",
		),
		(
			"owner = \"crates/clients/cli/src/report.rs\"",
			"owner = \"../report.rs\"",
			"expected owner",
		),
	] {
		let altered = CURRENT.replacen(from, to, 1);
		assert_ne!(CURRENT, altered, "mutation must change fixture: {from}");
		let mut findings = Findings::default();
		check_text(root(), Path::new(INVENTORY), &altered, &mut findings);
		assert!(findings.to_string().contains(expected), "{findings}");
	}
}

#[test]
fn detects_cli_version_and_id_drift_in_report_initializers() {
	let fixture = Fixture::new();
	let record: Contract = toml::from_str(DIFF).expect("parse fixture contract");
	let owner = "crates/clients/cli/src/report.rs";
	fixture.write(
		owner,
		r#"fn report() -> Report { Report { schema: "exacopy.cli.diff", schema_version: "1.0" } }"#,
	);
	assert_eq!(check_record(fixture.root(), &record), Ok(()));
	fixture.write(
		owner,
		r#"fn report() -> Report { Report { schema: "exacopy.cli.diff", schema_version: "2.0" } }"#,
	);
	let error = check_record(fixture.root(), &record).expect_err("reject changed version");
	assert!(error.contains("version differs from 2.0"), "{error}");
	fixture.write(
		owner,
		r#"fn report() -> Report { Report { schema: "exacopy.cli.copy", schema_version: "1.0" } }"#,
	);
	let error = check_record(fixture.root(), &record).expect_err("reject changed schema");
	assert!(error.contains("schema identifier differs"), "{error}");
}

#[test]
fn refuses_comment_only_and_duplicate_constants() {
	let fixture = Fixture::new();
	let record: Contract = toml::from_str(FRAME).expect("parse fixture contract");
	let owner = "crates/storage/journal/src/frame.rs";
	let magic = r#"const MAGIC: &[u8; 8] = b"EXAJNL01";"#;
	for version in [
		"// const VERSION: u16 = 1;",
		"const VERSION: u16 = 1;\nconst VERSION: u16 = 2;",
	] {
		fixture.write(owner, &format!("{magic}\n{version}"));
		let error =
			check_record(fixture.root(), &record).expect_err("reject absent or duplicate version");
		assert!(
			error.contains("expected one top-level VERSION constant"),
			"{error}"
		);
	}
	fixture.write(
		owner,
		r#"const VERSION: u16 = 1; const MAGIC: &[u8; 8] = b"EXAJNL02";"#,
	);
	let error = check_record(fixture.root(), &record).expect_err("reject changed magic");
	assert!(error.contains("magic differs"), "{error}");
}

#[test]
fn detects_private_required_feature_drift() {
	let fixture = Fixture::new();
	let record: Contract = toml::from_str(PLAN).expect("parse fixture contract");
	let owner = "crates/operations/transfer/src/macos/plan/wire.rs";
	fixture.write(owner, "const VERSION: [u8; 3] = [2, 0, 3];");
	let error =
		check_record(fixture.root(), &record).expect_err("reject changed required feature mask");
	assert!(
		error.contains("required feature mask differs from Some(3)"),
		"{error}"
	);
	fixture.write(owner, "const VERSION: [u8; 3] = [2, 0, 1];");
	assert_eq!(check_record(fixture.root(), &record), Ok(()));
}
