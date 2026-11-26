use super::Marker;

const NAMED: Marker = Marker::array("RESOLVED_DIRECT_VERSION", 3);

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
