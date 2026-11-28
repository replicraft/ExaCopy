use super::Marker;

#[test]
fn owned_report_strings_require_literal_values_in_any_scope() {
	for initializer in [
		r#"Report { schema: "fixture.report", schema_version: "1.0" }"#,
		r#"Report { schema: "fixture.report".into(), schema_version: "1.0".into() }"#,
	] {
		let file = syn::parse_file(&format!("fn build() {{ {initializer}; }}"))
			.expect("parse literal report fixture");
		assert_eq!(
			super::schema::report_version(&file, "fixture.report"),
			Ok("1.0".into())
		);
	}
	for source in [
		r#"const VERSION: &str = "1.0"; fn build() { Report { schema: "fixture.report".into(), schema_version: VERSION.into() }; }"#,
		r#"const VERSION: &str = "1.0"; fn build() { const VERSION: &str = "2.0"; Report { schema: "fixture.report".into(), schema_version: VERSION.into() }; }"#,
		r#"const VERSION: &str = "1.0"; mod nested { const VERSION: &str = "2.0"; fn build() { Report { schema: "fixture.report".into(), schema_version: VERSION.into() }; } }"#,
		r#"fn build() { Report { schema: "fixture.report".into(1), schema_version: "1.0".into() }; }"#,
		r#"fn build() { Report { schema: "fixture.report".into(), schema_version: "01.0".into() }; }"#,
		r#"fn build() { Report { schema: "fixture.report".into(), schema_version: get_version() }; }"#,
	] {
		let file = syn::parse_file(source).expect("parse refused report fixture");
		assert!(
			super::schema::report_version(&file, "fixture.report").is_err(),
			"{source}"
		);
	}
}

#[test]
fn named_page_version_keeps_document_page_classification() {
	use super::super::Contract;
	use crate::test_support::Fixture;

	let fixture = Fixture::new();
	fixture.write(
		"page.rs",
		"const VERSION: [u64; 2] = [9, 9]; const ACTION_PAGE_VERSION: [u64; 2] = [1, 0];",
	);
	let record: Contract = toml::from_str(
		r#"id = "fixture-page"
kind = "document_page"
status = "implemented"
version = "1.0"
owner = "page.rs"
"#,
	)
	.expect("parse page contract");
	let binding = super::Binding::new(
		"fixture-page",
		"page.rs",
		Marker::NamedDocumentPage {
			version: "ACTION_PAGE_VERSION",
		},
	);
	assert_eq!(binding.check(fixture.root(), &record), Ok(()));
	let wrong: Contract = toml::from_str(
		r#"id = "fixture-page"
kind = "transfer_journal"
status = "implemented_private"
version = "1.0"
owner = "page.rs"
"#,
	)
	.expect("parse wrong contract class");
	assert!(binding.check(fixture.root(), &wrong).is_err());
}

const NAMED: Marker = Marker::array("RESOLVED_DIRECT_VERSION", 3);

#[test]
fn magic_suffix_reads_the_selected_top_level_version() {
	let marker = Marker::MagicSuffix {
		magic: "MAGIC",
		width: 2,
	};
	let file = syn::parse_file("const MAGIC: &[u8; 8] = b\"EXLPQA01\";")
		.expect("parse qualification magic");
	let actual = marker.read(&file, "fixture").expect("read magic version");
	assert_eq!(actual.version, "1");
	assert_eq!(actual.magic.as_deref(), Some("EXLPQA01"));
	assert_eq!(actual.features, None);
	for source in [
		"const MAGIC: &[u8; 8] = b\"EXLPQA0x\";",
		"const MAGIC: &[u8; 1] = b\"1\";",
		"const MAGIC: &[u8; 8] = OTHER;",
		"mod decoy { const MAGIC: &[u8; 8] = b\"EXLPQA01\"; }",
		"const MAGIC: &[u8; 8] = b\"EXLPQA01\"; const MAGIC: &[u8; 8] = b\"EXLPQA02\";",
	] {
		let file = syn::parse_file(source).expect("parse invalid marker fixture");
		assert!(marker.read(&file, "fixture").is_err(), "{source}");
	}
}

#[test]
fn exact_array_name_selects_its_own_top_level_profile() {
	let file = syn::parse_file(
		"const VERSION: [u64; 3] = [1, 0, 1];
		const RESOLVED_DIRECT_VERSION: [u64; 3] = [1, 1, 3];
		const ABSOLUTE_PATH_VERSION: [u64; 3] = [1, 2, 7];
		mod decoy { const RESOLVED_DIRECT_VERSION: [u64; 3] = [8, 0, 0]; }",
	)
	.expect("parse fixture");
	for (marker, version, features) in [
		(Marker::array("VERSION", 3), "1.0", 1),
		(NAMED, "1.1", 3),
		(Marker::array("ABSOLUTE_PATH_VERSION", 3), "1.2", 7),
	] {
		let actual = marker.read(&file, "fixture").expect("read one named array");
		assert_eq!(actual.version, version);
		assert_eq!(actual.features, Some(features));
		assert_eq!(actual.magic, None);
	}
}

#[test]
fn missing_nested_comment_and_duplicate_named_arrays_refuse() {
	for source in [
		"const VERSION: [u64; 3] = [1, 1, 3];",
		"const RESOLVED_DIRECT_VERSION_SHADOW: [u64; 3] = [1, 1, 3];",
		"// const RESOLVED_DIRECT_VERSION: [u64; 3] = [1, 1, 3];",
		"mod hidden { const RESOLVED_DIRECT_VERSION: [u64; 3] = [1, 1, 3]; }",
		"impl Fixture { const RESOLVED_DIRECT_VERSION: [u64; 3] = [1, 1, 3]; }",
		"const RESOLVED_DIRECT_VERSION: [u64; 3] = [1, 1, 3];
		#[cfg(any())] const RESOLVED_DIRECT_VERSION: [u64; 3] = [1, 1, 3];",
	] {
		let file = syn::parse_file(source).expect("parse invalid marker fixture");
		assert_eq!(
			NAMED.read(&file, "fixture").err().as_deref(),
			Some("expected one top-level RESOLVED_DIRECT_VERSION constant"),
			"{source}",
		);
	}
}

#[test]
fn selected_array_requires_exact_width_and_unsigned_literal_values() {
	for (source, expected) in [
		(
			"const RESOLVED_DIRECT_VERSION: u64 = 3;",
			"expected a RESOLVED_DIRECT_VERSION array",
		),
		(
			"const RESOLVED_DIRECT_VERSION: [u64; 2] = [1, 1];",
			"expected 3 entries in RESOLVED_DIRECT_VERSION",
		),
		(
			"const RESOLVED_DIRECT_VERSION: [u64; 3] = [1, 1, FLAGS];",
			"expected a literal unsigned integer marker",
		),
	] {
		let file = syn::parse_file(source).expect("parse invalid marker fixture");
		assert_eq!(
			NAMED.read(&file, "fixture").err().as_deref(),
			Some(expected)
		);
	}
}
