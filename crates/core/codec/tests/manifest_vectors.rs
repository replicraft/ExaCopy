//! Cross-language golden vectors for the single-file manifest.
use exacopy_codec::SingleFileManifest;

#[test]
fn independent_vectors_match_canonical_body_and_envelope_digest() {
	let vectors: [ManifestVector; 3] = [
		ManifestVector(
			include_bytes!("../verification/manifest/vectors/empty-nonutf8.json"),
			include_bytes!("../verification/manifest/vectors/empty-nonutf8.canonical.cbor"),
			b"\xff.bin",
			0,
			*blake3::hash(b"").as_bytes(),
		),
		ManifestVector(
			include_bytes!("../verification/manifest/vectors/embedded-nonutf8.json"),
			include_bytes!("../verification/manifest/vectors/embedded-nonutf8.canonical.cbor"),
			b"prefix-\xff-suffix.bin",
			3,
			*blake3::hash(b"abc").as_bytes(),
		),
		ManifestVector(
			include_bytes!("../verification/manifest/vectors/max-length.json"),
			include_bytes!("../verification/manifest/vectors/max-length.canonical.cbor"),
			b"\xff.bin",
			i64::MAX as u64,
			core::array::from_fn(|index| u8::try_from(index).unwrap()),
		),
	];
	for ManifestVector(expected_json, expected_cbor, basename, length, file_digest) in vectors {
		let manifest = SingleFileManifest::from_json(expected_json).unwrap();
		assert_eq!(manifest.basename(), basename);
		assert_eq!(manifest.length(), length);
		assert_eq!(manifest.content_digest(), file_digest);
		assert_eq!(manifest.canonical_body(), expected_cbor);
		let actual: serde_json::Value =
			serde_json::from_slice(&manifest.to_json().unwrap()).unwrap();
		let expected: serde_json::Value = serde_json::from_slice(expected_json).unwrap();
		assert_eq!(actual, expected);
	}
}

struct ManifestVector(&'static [u8], &'static [u8], &'static [u8], u64, [u8; 32]);

#[test]
fn independent_display_annotation_changes_no_canonical_byte() {
	let annotated =
		include_bytes!("../verification/manifest/vectors/embedded-nonutf8.display-input.json");
	let plain = include_bytes!("../verification/manifest/vectors/embedded-nonutf8.json");
	assert_eq!(
		SingleFileManifest::from_json(annotated),
		SingleFileManifest::from_json(plain)
	);
}
