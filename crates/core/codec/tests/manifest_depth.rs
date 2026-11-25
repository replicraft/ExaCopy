//! Structural depth limits apply before unsupported values can reach recursive visitors.

use exacopy_codec::{ManifestError, ManifestInvalid, ManifestUnsupported, SingleFileManifest};

const GOLDEN: &[u8] = include_bytes!("../verification/manifest/vectors/empty-nonutf8.json");

fn nested_extension(arrays: usize) -> Vec<u8> {
	let mut document: serde_json::Value = serde_json::from_slice(GOLDEN).unwrap();
	let mut nested = serde_json::Value::Null;
	for _ in 0..arrays {
		nested = serde_json::Value::Array(vec![nested]);
	}
	document["body"]["extensions"]["test.nesting"] = nested;
	serde_json::to_vec(&document).unwrap()
}

#[test]
fn caps_nesting_even_inside_unsupported_values() {
	// Envelope, body and extension maps occupy the first three levels.
	assert_eq!(
		SingleFileManifest::from_json(&nested_extension(29)),
		Err(ManifestError::Unsupported(
			ManifestUnsupported::AdditionalData
		))
	);
	assert_eq!(
		SingleFileManifest::from_json(&nested_extension(30)),
		Err(ManifestError::Invalid(ManifestInvalid::Depth))
	);
}

#[test]
fn escaped_quotes_and_container_bytes_in_display_are_not_structure() {
	let expected = SingleFileManifest::from_json(GOLDEN).unwrap();
	let mut document: serde_json::Value = serde_json::from_slice(GOLDEN).unwrap();
	document["body"]["entries"][0]["path"]["display"] =
		serde_json::Value::String("[\\\"{}]".repeat(128));
	assert_eq!(
		SingleFileManifest::from_json(&serde_json::to_vec(&document).unwrap()).unwrap(),
		expected
	);
}

#[test]
fn refuses_unbalanced_or_incomplete_containers() {
	for input in [b"{".as_slice(), b"{]", b"}", b"{\"display\":\"\\"] {
		assert_eq!(
			SingleFileManifest::from_json(input),
			Err(ManifestError::Invalid(ManifestInvalid::Json)),
			"{input:?}"
		);
	}
}
