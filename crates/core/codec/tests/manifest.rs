//! Validation and compatibility checks for the single-file manifest JSON profile.
use exacopy_codec::{
	MAX_MANIFEST_JSON_BYTES, ManifestError, ManifestInvalid, ManifestUnsupported,
	SingleFileManifest,
};
use serde_json::{Value, json};
use uuid::Uuid;

const MANIFEST_ID: Uuid = Uuid::from_u128(0x18291f52_8015_48ff_af49_546767ec49cd);
const ROOT_ID: Uuid = Uuid::from_u128(0xe57d5e90_ad55_446e_a983_4cc60a94290a);

fn example() -> SingleFileManifest {
	SingleFileManifest::new(
		MANIFEST_ID,
		ROOT_ID,
		b"raw-\xff.bin",
		3,
		*blake3::hash(b"abc").as_bytes(),
	)
	.expect("known profile")
}

fn envelope() -> Value {
	serde_json::from_slice(&example().to_json().unwrap()).expect("encoded envelope")
}

fn decode(value: &Value) -> Result<SingleFileManifest, ManifestError> {
	SingleFileManifest::from_json(&serde_json::to_vec(value).unwrap())
}

#[test]
fn supported_shape_preserves_lossless_observation() {
	let manifest = example();
	let encoded = manifest.to_json().unwrap();
	assert_eq!(
		SingleFileManifest::from_json(&encoded),
		Ok(manifest.clone())
	);
	let equivalent = serde_json::to_vec_pretty(&envelope()).unwrap();
	assert_eq!(
		SingleFileManifest::from_json(&equivalent),
		Ok(manifest.clone())
	);
	assert_eq!(manifest.manifest_id(), MANIFEST_ID);
	assert_eq!(manifest.root_id(), ROOT_ID);
	assert_eq!(manifest.basename(), b"raw-\xff.bin");
	assert_eq!(manifest.length(), 3);
	assert_eq!(manifest.content_digest(), *blake3::hash(b"abc").as_bytes());

	let mut annotated = envelope();
	annotated["body"]["entries"][0]["path"]["display"] = json!("/looks/absolute");
	assert_eq!(decode(&annotated), Ok(manifest));
}

#[test]
fn primitive_values_respect_the_supported_wire_encoding() {
	let cases = [
		(
			"/body/manifest_id",
			json!("18291f52801548ffaf49546767ec49cd"),
			ManifestInvalid::Identifier,
		),
		(
			"/body/manifest_id",
			json!("18291F52-8015-48FF-AF49-546767EC49CD"),
			ManifestInvalid::Identifier,
		),
		(
			"/body/entries/0/path/root_id",
			json!("00000000-0000-0000-0000-000000000000"),
			ManifestInvalid::Identifier,
		),
		(
			"/body/entries/0/path/components/0/raw_base64",
			json!("Zg"),
			ManifestInvalid::Base64,
		),
		(
			"/body/entries/0/path/components/0/raw_base64",
			json!("Zh=="),
			ManifestInvalid::Base64,
		),
		(
			"/body/entries/0/path/components/0/raw_base64",
			json!("Li4="),
			ManifestInvalid::Basename,
		),
		(
			"/body/entries/0/path/components/0/raw_base64",
			json!("Lw=="),
			ManifestInvalid::Basename,
		),
		(
			"/body/entries/0/path/components/0/raw_base64",
			json!("AA=="),
			ManifestInvalid::Basename,
		),
		(
			"/body/entries/0/streams/0/length",
			json!("03"),
			ManifestInvalid::Length,
		),
		(
			"/body/entries/0/streams/0/length",
			json!("+3"),
			ManifestInvalid::Length,
		),
		(
			"/body/entries/0/streams/0/length",
			json!("9223372036854775808"),
			ManifestInvalid::Length,
		),
		(
			"/body/entries/0/streams/0/length",
			json!("18446744073709551616"),
			ManifestInvalid::Length,
		),
		(
			"/body/entries/0/streams/0/length",
			json!(3),
			ManifestInvalid::Json,
		),
		(
			"/body/entries/0/streams/0/digest",
			json!("abc"),
			ManifestInvalid::Digest,
		),
		(
			"/body/entries/0/path/components/0/encoding",
			json!("utf8"),
			ManifestInvalid::Enum,
		),
	];
	for (pointer, value, expected) in cases {
		let mut candidate = envelope();
		*candidate.pointer_mut(pointer).unwrap() = value;
		assert_eq!(
			decode(&candidate),
			Err(ManifestError::Invalid(expected)),
			"{pointer}"
		);
	}
}

#[test]
fn known_unsupported_profiles_are_never_downgraded() {
	let cases = [
		(
			"/body/schema_version",
			json!("2.0"),
			ManifestUnsupported::Version,
		),
		(
			"/body/algorithm",
			json!("sha256"),
			ManifestUnsupported::Algorithm,
		),
		(
			"/body/consistency",
			json!("tree_snapshot"),
			ManifestUnsupported::Observation,
		),
		(
			"/body/complete",
			json!(false),
			ManifestUnsupported::Observation,
		),
		(
			"/body/entries/0/file_type",
			json!("directory"),
			ManifestUnsupported::Shape,
		),
		(
			"/body/entries/0/path/components/0/encoding",
			json!("windows_utf16le"),
			ManifestUnsupported::Shape,
		),
		(
			"/body/entries/0/streams/0/name_raw_base64",
			json!("bmFtZQ=="),
			ManifestUnsupported::Shape,
		),
		(
			"/body/entries/0/streams",
			json!([]),
			ManifestUnsupported::Shape,
		),
		(
			"/body/entries/0/path/components",
			json!([]),
			ManifestUnsupported::Shape,
		),
		(
			"/body/entries/0/metadata_ref",
			json!({}),
			ManifestUnsupported::AdditionalData,
		),
		(
			"/body/continuation_pages",
			json!([{}]),
			ManifestUnsupported::AdditionalData,
		),
		(
			"/body/errors",
			json!([{}]),
			ManifestUnsupported::AdditionalData,
		),
		(
			"/body/extensions",
			json!({"example.addon":1}),
			ManifestUnsupported::AdditionalData,
		),
	];
	for (pointer, value, expected) in cases {
		let mut candidate = envelope();
		*candidate.pointer_mut(pointer).unwrap() = value;
		assert_eq!(
			decode(&candidate),
			Err(ManifestError::Unsupported(expected)),
			"{pointer}"
		);
	}

	let mut signed = envelope();
	signed["signature"] =
		json!({"algorithm":"Ed25519","public_key_base64":"","signature_base64":""});
	assert_eq!(
		decode(&signed),
		Err(ManifestUnsupported::AdditionalData.into())
	);

	let mut multiple = envelope();
	let entries = multiple["body"]["entries"].as_array_mut().unwrap();
	entries.push(entries[0].clone());
	assert_eq!(decode(&multiple), Err(ManifestUnsupported::Shape.into()));
}

#[test]
fn malformed_objects_duplicates_trailing_data_and_oversize_fail() {
	let encoded = String::from_utf8(example().to_json().unwrap()).unwrap();
	let mut envelope_without_required_null = envelope();
	envelope_without_required_null["body"]["entries"][0]
		.as_object_mut()
		.unwrap()
		.remove("metadata_ref");
	assert_eq!(
		decode(&envelope_without_required_null),
		Err(ManifestInvalid::Json.into())
	);

	let mut annotated_null = envelope();
	annotated_null["body"]["entries"][0]["path"]["display"] = Value::Null;
	assert_eq!(decode(&annotated_null), Err(ManifestInvalid::Json.into()));

	for malformed in [
		format!("{encoded} {{}}"),
		encoded.replacen(
			"\"complete\":true",
			"\"complete\":true,\"complete\":true",
			1,
		),
		encoded.replacen("\"complete\":true", "\"complete\":true,\"unknown\":true", 1),
		encoded.replacen("\"extensions\":{}", "\"extensions\":[]", 1),
		encoded.replacen(
			"{\"encoding\":\"unix_bytes\",\"raw_base64\":\"cmF3Lf8uYmlu\"}",
			"[\"unix_bytes\",\"cmF3Lf8uYmlu\"]",
			1,
		),
	] {
		assert_eq!(
			SingleFileManifest::from_json(malformed.as_bytes()),
			Err(ManifestInvalid::Json.into())
		);
	}

	for boundary in 0..encoded.len() {
		assert!(SingleFileManifest::from_json(&encoded.as_bytes()[..boundary]).is_err());
	}
	assert_eq!(
		SingleFileManifest::from_json(&vec![b' '; MAX_MANIFEST_JSON_BYTES + 1]),
		Err(ManifestInvalid::Size.into())
	);
	let mut at_limit = encoded.into_bytes();
	at_limit.resize(MAX_MANIFEST_JSON_BYTES, b' ');
	assert_eq!(SingleFileManifest::from_json(&at_limit), Ok(example()));
}

#[test]
fn well_formed_digest_changes_are_integrity_failures() {
	let mut wrong_digest = envelope();
	wrong_digest["digest"] = json!("00".repeat(32));
	assert_eq!(decode(&wrong_digest), Err(ManifestError::Integrity));

	let mut renamed = envelope();
	renamed["body"]["entries"][0]["path"]["components"][0]["raw_base64"] = json!("bmV3");
	assert_eq!(decode(&renamed), Err(ManifestError::Integrity));
}

#[test]
fn constructor_checks_limits_without_filesystem_effects() {
	let digest = *blake3::hash(b"").as_bytes();
	for invalid in [&b""[..], b".", b"..", b"a/b", b"nul\0name", &[b'a'; 256]] {
		assert_eq!(
			SingleFileManifest::new(MANIFEST_ID, ROOT_ID, invalid, 0, digest),
			Err(ManifestInvalid::Basename.into())
		);
	}
	let longest =
		SingleFileManifest::new(MANIFEST_ID, ROOT_ID, &[b'a'; 255], i64::MAX as u64, digest)
			.unwrap();
	assert_eq!(
		SingleFileManifest::from_json(&longest.to_json().unwrap()),
		Ok(longest)
	);
	assert_eq!(
		SingleFileManifest::new(MANIFEST_ID, ROOT_ID, b"a", i64::MAX as u64 + 1, digest),
		Err(ManifestInvalid::Length.into())
	);
	assert_eq!(
		SingleFileManifest::new(Uuid::nil(), ROOT_ID, b"a", 0, digest),
		Err(ManifestInvalid::Identifier.into())
	);
}
