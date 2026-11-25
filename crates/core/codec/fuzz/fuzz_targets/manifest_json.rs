//! Exercises rejection and semantic round trips of portable manifest JSON.
#![no_main]
#![forbid(unsafe_code)]

use exacopy_codec::{MAX_MANIFEST_JSON_BYTES, ManifestError, ManifestInvalid, SingleFileManifest};
use libfuzzer_sys::fuzz_target;

fn check_manifest(input: &[u8]) {
	let parsed = SingleFileManifest::from_json(input);
	if input.len() > MAX_MANIFEST_JSON_BYTES {
		assert_eq!(parsed, Err(ManifestInvalid::Size.into()));
		return;
	}

	match parsed {
		Ok(manifest) => check_round_trip(&manifest),
		Err(error) => {
			// Rejection categories depend on the record, not parser state.
			assert_eq!(SingleFileManifest::from_json(input), Err(error));
		}
	}
}

fn check_round_trip(manifest: &SingleFileManifest) {
	let basename = manifest.basename();
	assert!(!basename.is_empty() && basename.len() <= 255);
	assert!(!matches!(basename, b"." | b".."));
	assert!(!basename.iter().any(|byte| matches!(byte, 0 | b'/')));
	assert!(!manifest.manifest_id().is_nil() && !manifest.root_id().is_nil());
	assert!(manifest.length() <= i64::MAX as u64);

	let mut encoded = manifest
		.to_json()
		.expect("an admitted manifest has a JSON projection");
	assert!(encoded.len() <= MAX_MANIFEST_JSON_BYTES);
	let reparsed =
		SingleFileManifest::from_json(&encoded).expect("the writer emitted an invalid envelope");
	assert_eq!(&reparsed, manifest);
	assert_eq!(reparsed.canonical_body(), manifest.canonical_body());
	assert_eq!(reparsed.digest(), manifest.digest());

	encoded.push(b'x');
	assert_eq!(
		SingleFileManifest::from_json(&encoded),
		Err(ManifestError::Invalid(ManifestInvalid::Json))
	);
}

fuzz_target!(|input: &[u8]| check_manifest(input));
