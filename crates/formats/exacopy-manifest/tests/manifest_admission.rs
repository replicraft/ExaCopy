//! Wire admission and diagnostic privacy of the public single-file manifest.

use base64::{Engine, engine::general_purpose::STANDARD};
use exacopy_manifest::{
	MAX_MANIFEST_JSON_BYTES, ManifestError, ManifestInvalid, ManifestUnsupported,
	SingleFileManifest,
};
use serde_json::{Value, json};
use uuid::Uuid;

const GOLDEN: &[u8] = include_bytes!("../verification/manifest/vectors/empty-nonutf8.json");
const PRIVATE_MARKER: &str = "private-manifest-token";
const HOSTILE_DISPLAY: &str = "/private-manifest-token/\u{1b}[31m";

fn annotated_envelope() -> Value {
	let mut document: Value = serde_json::from_slice(GOLDEN).unwrap();
	document["body"]["entries"][0]["path"]["display"] = json!(HOSTILE_DISPLAY);
	document
}

fn assert_private_error(
	result: Result<SingleFileManifest, ManifestError>,
	expected: ManifestError,
	sensitive: &str,
) {
	let error = result.expect_err("manifest must be rejected");
	assert_eq!(error, expected);
	for rendered in [error.to_string(), format!("{error:?}")] {
		assert!(!rendered.is_empty() && rendered.len() <= 256);
		assert!(rendered.bytes().all(|b| b.is_ascii_graphic() || b == b' '));
		assert!(!rendered.contains(PRIVATE_MARKER));
		assert!(sensitive.is_empty() || !rendered.contains(sensitive));
	}
}

#[test]
fn malformed_wire_values_keep_typed_private_diagnostics() {
	let too_long = STANDARD.encode([b'x'; 256]);
	let invalid_hex = "X".repeat(64);
	let cases = [
		(
			"/body/manifest_id",
			json!(HOSTILE_DISPLAY),
			ManifestInvalid::Identifier,
		),
		(
			"/body/entries/0/path/components/0/raw_base64",
			json!(too_long),
			ManifestInvalid::Basename,
		),
		(
			"/body/entries/0/streams/0/length",
			json!(""),
			ManifestInvalid::Length,
		),
		(
			"/body/entries/0/streams/0/name_raw_base64",
			json!(HOSTILE_DISPLAY),
			ManifestInvalid::Base64,
		),
		(
			"/body/entries/0/streams/0/digest",
			json!(invalid_hex),
			ManifestInvalid::Digest,
		),
		(
			"/body/algorithm",
			json!(HOSTILE_DISPLAY),
			ManifestInvalid::Enum,
		),
		(
			"/body/consistency",
			json!(HOSTILE_DISPLAY),
			ManifestInvalid::Enum,
		),
		(
			"/body/entries/0/file_type",
			json!(HOSTILE_DISPLAY),
			ManifestInvalid::Enum,
		),
	];
	for (pointer, value, expected) in cases {
		let mut document = annotated_envelope();
		let sensitive = value.as_str().unwrap().to_owned();
		*document.pointer_mut(pointer).unwrap() = value;
		assert_private_error(
			SingleFileManifest::from_json(&serde_json::to_vec(&document).unwrap()),
			expected.into(),
			&sensitive,
		);
	}

	let mut document = annotated_envelope();
	document[PRIVATE_MARKER] = json!(HOSTILE_DISPLAY);
	assert_private_error(
		SingleFileManifest::from_json(&serde_json::to_vec(&document).unwrap()),
		ManifestInvalid::Json.into(),
		HOSTILE_DISPLAY,
	);

	let malformed = format!(r#"{{"{PRIVATE_MARKER}":}}"#);
	assert_private_error(
		SingleFileManifest::from_json(malformed.as_bytes()),
		ManifestInvalid::Json.into(),
		&malformed,
	);

	let too_large = format!("{HOSTILE_DISPLAY}{}", " ".repeat(MAX_MANIFEST_JSON_BYTES));
	assert_private_error(
		SingleFileManifest::from_json(too_large.as_bytes()),
		ManifestInvalid::Size.into(),
		HOSTILE_DISPLAY,
	);

	let too_deep = format!(
		"{}{}{}",
		"[".repeat(33),
		serde_json::to_string(HOSTILE_DISPLAY).unwrap(),
		"]".repeat(33)
	);
	assert_private_error(
		SingleFileManifest::from_json(too_deep.as_bytes()),
		ManifestInvalid::Depth.into(),
		HOSTILE_DISPLAY,
	);
}

#[test]
fn unsupported_records_are_rejected_without_echoing_annotations() {
	let symlink_target = STANDARD.encode(HOSTILE_DISPLAY);
	let cases = [
		(
			"/body/schema_version",
			json!(HOSTILE_DISPLAY),
			ManifestUnsupported::Version,
		),
		(
			"/body/algorithm",
			json!("sha256"),
			ManifestUnsupported::Algorithm,
		),
		(
			"/body/consistency",
			json!("file_stable"),
			ManifestUnsupported::Observation,
		),
		(
			"/body/entries/0/metadata_ref",
			json!({"path": HOSTILE_DISPLAY}),
			ManifestUnsupported::AdditionalData,
		),
	];
	for (pointer, value, expected) in cases {
		let mut document = annotated_envelope();
		*document.pointer_mut(pointer).unwrap() = value;
		assert_private_error(
			SingleFileManifest::from_json(&serde_json::to_vec(&document).unwrap()),
			expected.into(),
			HOSTILE_DISPLAY,
		);
	}

	let mut document = annotated_envelope();
	document["body"]["entries"][0]["symlink_target_base64"] = json!(symlink_target);
	assert_private_error(
		SingleFileManifest::from_json(&serde_json::to_vec(&document).unwrap()),
		ManifestUnsupported::Shape.into(),
		&symlink_target,
	);
}

#[test]
fn trailing_collection_items_cannot_qualify_the_first_entry() {
	let mut document = annotated_envelope();
	let entries = document["body"]["entries"].as_array_mut().unwrap();
	entries.extend([json!(null), json!({"display": HOSTILE_DISPLAY})]);
	assert_private_error(
		SingleFileManifest::from_json(&serde_json::to_vec(&document).unwrap()),
		ManifestUnsupported::Shape.into(),
		HOSTILE_DISPLAY,
	);
}

#[test]
fn digest_mismatch_diagnostic_keeps_the_supplied_digest_private() {
	let mut document = annotated_envelope();
	let different_digest = "e".repeat(64);
	document["digest"] = json!(different_digest);
	assert_private_error(
		SingleFileManifest::from_json(&serde_json::to_vec(&document).unwrap()),
		ManifestError::Integrity,
		&different_digest,
	);
}

#[test]
fn constructor_admits_maximum_basename_and_rejects_a_nil_root() {
	let example = SingleFileManifest::from_json(GOLDEN).unwrap();
	let basename = [b'x'; 255];
	let manifest = SingleFileManifest::new(
		example.manifest_id(),
		example.root_id(),
		&basename,
		example.length(),
		example.content_digest(),
	)
	.unwrap();
	assert_eq!(
		SingleFileManifest::from_json(&manifest.to_json().unwrap()),
		Ok(manifest)
	);

	assert_private_error(
		SingleFileManifest::new(
			example.manifest_id(),
			Uuid::nil(),
			&basename,
			example.length(),
			example.content_digest(),
		),
		ManifestInvalid::Identifier.into(),
		"",
	);
}

#[test]
fn manifest_debug_keeps_raw_basename_and_file_digest_private() {
	let example = SingleFileManifest::from_json(GOLDEN).unwrap();
	let basename = b"private-manifest-token\x1b[31m\xff";
	let digest = [203_u8; 32];
	let manifest = SingleFileManifest::new(
		example.manifest_id(),
		example.root_id(),
		basename,
		17,
		digest,
	)
	.unwrap();
	let rendered = format!("{manifest:?}");
	assert!(!rendered.contains(PRIVATE_MARKER));
	assert!(!rendered.contains(&format!("{basename:?}")));
	assert!(!rendered.contains(&format!("{digest:?}")));
	assert!(!rendered.contains(&"cb".repeat(32)));
	assert!(rendered.bytes().all(|b| b.is_ascii_graphic() || b == b' '));
}
