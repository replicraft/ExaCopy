use core::{fmt, marker::PhantomData};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use exacopy_core::MAX_UNIX_COMPONENT_BYTES;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
	MAX_MANIFEST_JSON_BYTES, ManifestError, ManifestInvalid, ManifestUnsupported,
	SingleFileManifest,
};

const SCHEMA_VERSION: &str = "1.0";
const BLAKE3: &str = "blake3-256";
const LIVE_OBSERVED: &str = "live_observed";
const REGULAR: &str = "regular";
const UNIX_BYTES: &str = "unix_bytes";
const MAX_ENCODED_BASENAME_BYTES: usize = MAX_UNIX_COMPONENT_BYTES.div_ceil(3) * 4;

mod limits;

pub(super) fn decode(input: &[u8]) -> Result<SingleFileManifest, ManifestError> {
	if input.len() > MAX_MANIFEST_JSON_BYTES {
		return Err(ManifestInvalid::Size.into());
	}
	limits::check(input)?;
	let Object(envelope): Object<Envelope> =
		serde_json::from_slice(input).map_err(|_| ManifestInvalid::Json)?;
	let expected = parse_digest(&envelope.digest)?;
	let body = envelope.body.0;
	if body.schema_version != SCHEMA_VERSION {
		return Err(ManifestUnsupported::Version.into());
	}
	check_algorithm(&body.algorithm)?;
	match body.consistency.as_str() {
		LIVE_OBSERVED if body.complete => {}
		LIVE_OBSERVED | "file_stable" | "tree_snapshot" | "application_consistent" => {
			return Err(ManifestUnsupported::Observation.into());
		}
		_ => return Err(ManifestInvalid::Enum.into()),
	}
	if envelope.signature.is_some()
		|| !matches!(body.continuation_pages, Items::Empty)
		|| !matches!(body.errors, Items::Empty)
		|| body.extensions.nonempty
	{
		return Err(ManifestUnsupported::AdditionalData.into());
	}
	let Items::One(Object(entry)) = &body.entries else {
		return Err(ManifestUnsupported::Shape.into());
	};
	let manifest = decode_entry(&body.manifest_id, entry)?;
	if manifest.digest() != expected {
		return Err(ManifestError::Integrity);
	}
	Ok(manifest)
}

fn decode_entry(manifest_id: &str, entry: &Entry) -> Result<SingleFileManifest, ManifestError> {
	match entry.file_type.as_str() {
		REGULAR => {}
		"directory" | "symlink" => return Err(ManifestUnsupported::Shape.into()),
		_ => return Err(ManifestInvalid::Enum.into()),
	}
	if entry.symlink_target_base64.is_some() {
		return Err(ManifestUnsupported::Shape.into());
	}
	if entry.metadata_ref.is_some() {
		return Err(ManifestUnsupported::AdditionalData.into());
	}
	let path = &entry.path.0;
	let Items::One(Object(basename)) = &path.components else {
		return Err(ManifestUnsupported::Shape.into());
	};
	let Items::One(Object(stream)) = &entry.streams else {
		return Err(ManifestUnsupported::Shape.into());
	};
	match basename.encoding.as_str() {
		UNIX_BYTES => {}
		"windows_utf16le" => return Err(ManifestUnsupported::Shape.into()),
		_ => return Err(ManifestInvalid::Enum.into()),
	}
	if !stream.name_raw_base64.is_empty() {
		// A well-formed named stream is outside the portable subset.
		STANDARD
			.decode(&stream.name_raw_base64)
			.map_err(|_| ManifestInvalid::Base64)?;
		return Err(ManifestUnsupported::Shape.into());
	}
	check_algorithm(&stream.algorithm)?;
	let length = parse_length(&stream.length)?;
	let digest = parse_digest(&stream.digest)?;
	let basename = decode_basename(&basename.raw_base64)?;
	SingleFileManifest::new(
		parse_uuid(manifest_id)?,
		parse_uuid(&path.root_id)?,
		&basename,
		length,
		digest,
	)
}

fn check_algorithm(algorithm: &str) -> Result<(), ManifestError> {
	match algorithm {
		BLAKE3 => Ok(()),
		"sha256" => Err(ManifestUnsupported::Algorithm.into()),
		_ => Err(ManifestInvalid::Enum.into()),
	}
}

fn decode_basename(text: &str) -> Result<Vec<u8>, ManifestError> {
	if text.len() > MAX_ENCODED_BASENAME_BYTES {
		return Err(ManifestInvalid::Basename.into());
	}
	STANDARD
		.decode(text)
		.map_err(|_| ManifestInvalid::Base64.into())
}

fn parse_length(text: &str) -> Result<u64, ManifestInvalid> {
	if text.is_empty()
		|| !text.bytes().all(|byte| byte.is_ascii_digit())
		|| (text.len() > 1 && text.starts_with('0'))
	{
		return Err(ManifestInvalid::Length);
	}
	text.parse().map_err(|_| ManifestInvalid::Length)
}

fn parse_uuid(text: &str) -> Result<Uuid, ManifestInvalid> {
	let identifier = Uuid::parse_str(text).map_err(|_| ManifestInvalid::Identifier)?;
	if identifier.is_nil() || identifier.hyphenated().encode_lower(&mut [0; 36]) != text {
		return Err(ManifestInvalid::Identifier);
	}
	Ok(identifier)
}

fn parse_digest(text: &str) -> Result<[u8; 32], ManifestInvalid> {
	if text.len() != 64
		|| !text
			.bytes()
			.all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
	{
		return Err(ManifestInvalid::Digest);
	}
	blake3::Hash::from_hex(text)
		.map(|hash| *hash.as_bytes())
		.map_err(|_| ManifestInvalid::Digest)
}

pub(super) fn encode(manifest: &SingleFileManifest) -> Result<Vec<u8>, ManifestError> {
	let entry = EntryOutput {
		path: PathOutput {
			root_id: manifest.root_id().hyphenated().to_string(),
			components: [Component {
				encoding: UNIX_BYTES.to_owned(),
				raw_base64: STANDARD.encode(manifest.basename()),
			}],
		},
		file_type: REGULAR,
		streams: [Stream {
			name_raw_base64: String::new(),
			length: manifest.length().to_string(),
			algorithm: BLAKE3.to_owned(),
			digest: hex(manifest.content_digest()),
		}],
		metadata_ref: (),
	};
	let output = EnvelopeOutput {
		body: BodyOutput {
			schema_version: SCHEMA_VERSION,
			manifest_id: manifest.manifest_id().hyphenated().to_string(),
			algorithm: BLAKE3,
			consistency: LIVE_OBSERVED,
			complete: true,
			entries: [entry],
			continuation_pages: [],
			errors: [],
			extensions: EmptyObject {},
		},
		digest: hex(manifest.digest()),
	};
	serde_json::to_vec(&output).map_err(|_| ManifestInvalid::Json.into())
}

fn hex(bytes: [u8; 32]) -> String {
	blake3::Hash::from_bytes(bytes).to_hex().to_string()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
	body: Object<Body>,
	digest: String,
	#[serde(default, deserialize_with = "present")]
	signature: Option<ObjectPresence>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
	schema_version: String,
	manifest_id: String,
	algorithm: String,
	consistency: String,
	complete: bool,
	entries: Items<Object<Entry>>,
	continuation_pages: Items<ObjectPresence>,
	errors: Items<ObjectPresence>,
	extensions: ObjectPresence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
	path: Object<Path>,
	file_type: String,
	streams: Items<Object<Stream>>,
	#[serde(deserialize_with = "nullable")]
	metadata_ref: Option<ObjectPresence>,
	#[serde(default, deserialize_with = "present")]
	symlink_target_base64: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Path {
	root_id: String,
	components: Items<Object<Component>>,
	#[serde(default, rename = "display", deserialize_with = "present")]
	_display: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Component {
	encoding: String,
	raw_base64: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stream {
	name_raw_base64: String,
	length: String,
	algorithm: String,
	digest: String,
}

#[derive(Serialize)]
struct EnvelopeOutput {
	body: BodyOutput,
	digest: String,
}

#[derive(Serialize)]
struct BodyOutput {
	schema_version: &'static str,
	manifest_id: String,
	algorithm: &'static str,
	consistency: &'static str,
	complete: bool,
	entries: [EntryOutput; 1],
	continuation_pages: [(); 0],
	errors: [(); 0],
	extensions: EmptyObject,
}

#[derive(Serialize)]
struct EmptyObject {}

#[derive(Serialize)]
struct EntryOutput {
	path: PathOutput,
	file_type: &'static str,
	streams: [Stream; 1],
	metadata_ref: (),
}

#[derive(Serialize)]
struct PathOutput {
	root_id: String,
	components: [Component; 1],
}

fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
	D: Deserializer<'de>,
	T: Deserialize<'de>,
{
	T::deserialize(deserializer).map(Some)
}

fn nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
	D: Deserializer<'de>,
	T: Deserialize<'de>,
{
	Option::<T>::deserialize(deserializer)
}

// Serde can ordinarily deserialize a named struct from a positional array.
// JSON interoperability requires an object at every struct boundary.
struct Object<T>(T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		struct ObjectVisitor<T>(PhantomData<T>);

		impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
			type Value = Object<T>;

			fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
				formatter.write_str("a JSON object")
			}

			fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
				T::deserialize(de::value::MapAccessDeserializer::new(map)).map(Object)
			}
		}

		deserializer.deserialize_map(ObjectVisitor(PhantomData))
	}
}

// Retain at most one item. Oversized collection shapes cannot allocate an
// inventory even when they fit within the document byte budget.
enum Items<T> {
	Empty,
	One(T),
	Multiple,
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Items<T> {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		struct ItemsVisitor<T>(PhantomData<T>);

		impl<'de, T: Deserialize<'de>> Visitor<'de> for ItemsVisitor<T> {
			type Value = Items<T>;

			fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
				formatter.write_str("a JSON array")
			}

			fn visit_seq<S: SeqAccess<'de>>(
				self,
				mut sequence: S,
			) -> Result<Self::Value, S::Error> {
				let Some(first) = sequence.next_element::<T>()? else {
					return Ok(Items::Empty);
				};
				if sequence.next_element::<IgnoredAny>()?.is_none() {
					return Ok(Items::One(first));
				}
				while sequence.next_element::<IgnoredAny>()?.is_some() {}
				Ok(Items::Multiple)
			}
		}

		deserializer.deserialize_seq(ItemsVisitor(PhantomData))
	}
}

struct ObjectPresence {
	nonempty: bool,
}

impl<'de> Deserialize<'de> for ObjectPresence {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		struct PresenceVisitor;

		impl<'de> Visitor<'de> for PresenceVisitor {
			type Value = ObjectPresence;

			fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
				formatter.write_str("a JSON object")
			}

			fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
				let mut nonempty = false;
				while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
					nonempty = true;
				}
				Ok(ObjectPresence { nonempty })
			}
		}

		deserializer.deserialize_map(PresenceVisitor)
	}
}
