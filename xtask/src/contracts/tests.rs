use std::path::Path;

use super::{Contract, INVENTORY, check, check_record, check_text};
use crate::finding::Findings;
use crate::test_support::Fixture;

const CURRENT: &str = include_str!("../../../specs/contracts/versions.toml");
const DIFF: &str = r#"
id = "exacopy.cli.diff"
kind = "cli_output"
status = "implemented"
version = "1.0"
owner = "apps/exacopy-cli/src/report.rs"
"#;
const FRAME: &str = r#"
id = "local-journal-frame"
kind = "transfer_journal"
status = "implemented_private"
version = "1"
owner = "crates/storage/exacopy-journal/src/frame.rs"
magic = "EXAJNL01"
"#;
const PLAN: &str = r#"
id = "darwin-managed-apfs-copy-plan"
kind = "transfer_journal"
status = "implemented_private"
version = "2.0"
required_features = 1
owner = "crates/engines/exacopy-transfer/src/macos/plan/wire.rs"
"#;

const MANIFEST_OWNER: &str = "crates/formats/exacopy-manifest/src/manifest/json.rs";
const MANIFEST: &str = r#"
id = "portable-manifests"
kind = "manifest"
status = "implemented"
version = "1.0"
owner = "crates/formats/exacopy-manifest/src/manifest/json.rs"
"#;
const MANIFEST_SOURCE: &str = r#"const SCHEMA_VERSION: &str = "1.0";"#;

fn root() -> &'static Path {
	Path::new(env!("CARGO_MANIFEST_DIR"))
		.parent()
		.expect("xtask belongs to the workspace")
}

#[test]
fn public_plan_json_version_cannot_drift_from_the_inventory() {
	let fixture = Fixture::new();
	let owner = "crates/formats/exacopy-plan/src/plan/json.rs";
	let text = format!(
		r#"id = "public-plan-json"
kind = "plan"
status = "implemented"
version = "1.0"
owner = "{owner}"
"#
	);
	let record: Contract = toml::from_str(&text).unwrap();
	fixture.write(owner, r#"const VERSION: &str = "1.0";"#);
	assert_eq!(check_record(fixture.root(), &record), Ok(()));
	for source in [
		r#"const VERSION: &str = "2.0";"#,
		r#"const VERSION: &str = "01.0";"#,
		"const VERSION: [u8; 2] = [1, 0];",
	] {
		fixture.write(owner, source);
		assert!(check_record(fixture.root(), &record).is_err(), "{source}");
	}
}

#[test]
fn canonical_plan_body_has_its_own_version_and_kind_binding() {
	let fixture = Fixture::new();
	let owner = "crates/formats/exacopy-plan/src/plan/wire.rs";
	let text = format!(
		r#"id = "public-plan-body"
kind = "plan"
status = "implemented"
version = "1.0"
owner = "{owner}"
"#
	);
	let record: Contract = toml::from_str(&text).unwrap();
	fixture.write(owner, "const VERSION: [u8; 2] = [1, 0];");
	assert_eq!(check_record(fixture.root(), &record), Ok(()));
	fixture.write(owner, "const VERSION: [u8; 2] = [2, 0];");
	assert!(check_record(fixture.root(), &record).is_err());
	fixture.write(owner, "const VERSION: [u8; 2] = [1, 0];");
	let wrong_kind: Contract =
		toml::from_str(&text.replace("kind = \"plan\"", "kind = \"document_page\"")).unwrap();
	assert!(check_record(fixture.root(), &wrong_kind).is_err());
}

#[test]
fn public_page_version_is_bound_to_its_canonical_wire_marker() {
	let fixture = Fixture::new();
	let owner = "crates/formats/exacopy-plan/src/plan_entries/wire.rs";
	let text = format!(
		r#"id = "public-plan-entries-page"
kind = "document_page"
status = "implemented"
version = "1.0"
owner = "{owner}"
"#
	);
	let record: Contract = toml::from_str(&text).unwrap();
	fixture.write(owner, "const VERSION: [u8; 2] = [1, 0];");
	assert_eq!(check_record(fixture.root(), &record), Ok(()));
	for source in [
		"const VERSION: [u8; 2] = [2, 0];",
		"const VERSION: [u8; 3] = [1, 0, 0];",
		"const VERSION: &str = \"1.0\";",
	] {
		fixture.write(owner, source);
		assert!(check_record(fixture.root(), &record).is_err(), "{source}");
	}
	fixture.write(owner, "const VERSION: [u8; 2] = [1, 0];");
	let wrong_kind: Contract =
		toml::from_str(&text.replace("document_page", "transfer_journal")).unwrap();
	assert!(check_record(fixture.root(), &wrong_kind).is_err());
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
			"owner = \"apps/exacopy-cli/src/report.rs\"",
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
	let owner = "apps/exacopy-cli/src/report.rs";
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
	let owner = "crates/storage/exacopy-journal/src/frame.rs";
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
	let owner = "crates/engines/exacopy-transfer/src/macos/plan/wire.rs";
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

#[test]
fn manifest_binding_requires_one_canonical_version_literal() {
	let fixture = Fixture::new();
	let record: Contract = toml::from_str(MANIFEST).expect("parse manifest contract fixture");
	fixture.write(MANIFEST_OWNER, MANIFEST_SOURCE);
	assert_eq!(check_record(fixture.root(), &record), Ok(()));

	for (source, expected) in [
		(
			r#"const SCHEMA_VERSION: &str = "2.0";"#,
			"version differs from 2.0",
		),
		(
			r#"// const SCHEMA_VERSION: &str = "1.0";"#,
			"expected one top-level SCHEMA_VERSION constant",
		),
		(
			r#"mod nested { const SCHEMA_VERSION: &str = "1.0"; }"#,
			"expected one top-level SCHEMA_VERSION constant",
		),
		(
			r#"const SCHEMA_VERSION: &str = "1.0"; const SCHEMA_VERSION: &str = "2.0";"#,
			"expected one top-level SCHEMA_VERSION constant",
		),
		(
			r#"const SCHEMA_VERSION: &str = concat!("1", ".0");"#,
			"expected a literal schema_version string",
		),
		(
			r#"const SCHEMA_VERSION: &str = "01.0";"#,
			"expected canonical major.minor schema_version",
		),
		(
			r#"const SCHEMA_VERSION: &str = "1";"#,
			"expected major.minor schema_version",
		),
	] {
		fixture.write(MANIFEST_OWNER, source);
		let error =
			check_record(fixture.root(), &record).expect_err("refuse invalid manifest marker");
		assert!(error.contains(expected), "{source}: {error}");
	}
}

#[test]
fn manifest_binding_requires_public_status_kind_owner_and_exact_markers() {
	let fixture = Fixture::new();
	fixture.write(MANIFEST_OWNER, MANIFEST_SOURCE);
	for (from, to, expected) in [
		(
			"status = \"implemented\"",
			"status = \"planned\"",
			"expected kind Manifest and status Implemented",
		),
		(
			"status = \"implemented\"",
			"status = \"implemented_private\"",
			"expected kind Manifest and status Implemented",
		),
		(
			"kind = \"manifest\"",
			"kind = \"cli_output\"",
			"expected kind Manifest and status Implemented",
		),
		(MANIFEST_OWNER, "../json.rs", "expected owner"),
		(
			"version = \"1.0\"",
			"version = \"2.0\"",
			"version differs from 1.0",
		),
		(
			"version = \"1.0\"",
			"version = \"1.0\"\nrequired_features = 0",
			"required feature mask differs from None",
		),
		(
			"version = \"1.0\"",
			"version = \"1.0\"\nmagic = \"manifest\"",
			"magic differs from None",
		),
	] {
		let altered = MANIFEST.replacen(from, to, 1);
		assert_ne!(MANIFEST, altered, "mutation must change fixture: {from}");
		let record: Contract = toml::from_str(&altered).expect("parse altered manifest fixture");
		let error =
			check_record(fixture.root(), &record).expect_err("refuse invalid manifest record");
		assert!(error.contains(expected), "{altered}: {error}");
	}
}
