use core::fmt;

use minicbor::data::{Int, Type};
use minicbor::encode::{self, Write};
use minicbor::{Decoder, Encoder};
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::ser::{Error as _, SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::value::RawValue;

use super::super::{MAX_PLAN_BODY_BYTES, PlanExtensions};
use super::PlanJsonError;
use super::limits::{Items, to_json as bounded_json};

const MAX_ROOT_FIELDS: usize = 16;
const MAX_MAP_FIELDS: usize = 64;
const MAX_ARRAY_ITEMS: usize = 4_096;

pub(super) fn from_json(raw: &RawValue) -> Result<Vec<u8>, PlanJsonError> {
	let mut encoder = Encoder::new(CborBytes::default());
	write_map::<MAX_ROOT_FIELDS>(&mut encoder, raw.get())?;
	Ok(encoder.into_writer().0)
}

pub(super) fn to_json(extensions: PlanExtensions<'_>) -> Result<Box<RawValue>, PlanJsonError> {
	// The checked PlanExtensions value has already bounded count, depth, and size.
	let value = Value(extensions.as_canonical_cbor());
	let canonical = String::from_utf8(bounded_json(&value)?).map_err(|_| PlanJsonError::Json)?;
	RawValue::from_string(canonical).map_err(|_| PlanJsonError::Json)
}

#[derive(Default)]
struct CborBytes(Vec<u8>);

impl Write for CborBytes {
	type Error = PlanJsonError;

	fn write_all(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
		if bytes.len() > MAX_PLAN_BODY_BYTES - self.0.len() {
			return Err(PlanJsonError::Extension);
		}
		self.0.extend_from_slice(bytes);
		Ok(())
	}
}

impl From<encode::Error<PlanJsonError>> for PlanJsonError {
	fn from(_: encode::Error<PlanJsonError>) -> Self {
		Self::Extension
	}
}

fn write_map<const LIMIT: usize>(
	encoder: &mut Encoder<CborBytes>,
	text: &str,
) -> Result<(), PlanJsonError> {
	let mut map: Map<'_, LIMIT> =
		serde_json::from_str(text).map_err(|_| PlanJsonError::Extension)?;
	// Preferred-length CBOR text headers order by UTF-8 byte length, then bytes.
	map.0.sort_unstable_by(|(left, _), (right, _)| {
		left.len().cmp(&right.len()).then_with(|| left.cmp(right))
	});
	encoder.map(u64::try_from(map.0.len()).map_err(|_| PlanJsonError::Extension)?)?;
	for (key, raw) in map.0 {
		encoder.str(&key)?;
		write_value(encoder, raw.get())?;
	}
	Ok(())
}

fn write_value(encoder: &mut Encoder<CborBytes>, text: &str) -> Result<(), PlanJsonError> {
	match text.as_bytes().first() {
		Some(b'{') => write_map::<MAX_MAP_FIELDS>(encoder, text)?,
		Some(b'[') => {
			let Items(items): Items<&RawValue, MAX_ARRAY_ITEMS> =
				serde_json::from_str(text).map_err(|_| PlanJsonError::Extension)?;
			encoder.array(u64::try_from(items.len()).map_err(|_| PlanJsonError::Extension)?)?;
			for value in items {
				write_value(encoder, value.get())?;
			}
		}
		Some(b'"') => {
			let value: String = serde_json::from_str(text).map_err(|_| PlanJsonError::Extension)?;
			encoder.str(&value)?;
		}
		Some(b'n') => {
			encoder.null()?;
		}
		Some(b't' | b'f') => {
			encoder.bool(text == "true")?;
		}
		_ => {
			// A raw JSON value preserves the integral lexeme, including -2^64.
			// Floating-point and exponent representations are outside this profile.
			let integer = text.parse::<i128>().map_err(|_| PlanJsonError::Extension)?;
			encoder.int(Int::try_from(integer).map_err(|_| PlanJsonError::Extension)?)?;
		}
	}
	Ok(())
}

struct Map<'a, const LIMIT: usize>(Vec<(String, &'a RawValue)>);

impl<'de, const LIMIT: usize> Deserialize<'de> for Map<'de, LIMIT> {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		struct MapVisitor<const LIMIT: usize>;

		impl<'de, const LIMIT: usize> Visitor<'de> for MapVisitor<LIMIT> {
			type Value = Map<'de, LIMIT>;

			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				write!(f, "an extension object of at most {LIMIT} properties")
			}

			fn visit_map<M: MapAccess<'de>>(self, mut access: M) -> Result<Self::Value, M::Error> {
				let mut entries: Vec<(String, &RawValue)> = Vec::new();
				for _ in 0..LIMIT {
					let Some(key) = access.next_key::<String>()? else {
						return Ok(Map(entries));
					};
					if entries.iter().any(|(prior, _)| *prior == key) {
						return Err(de::Error::custom("duplicate extension key"));
					}
					entries.push((key, access.next_value()?));
				}
				if access.next_key::<IgnoredAny>()?.is_some() {
					return Err(de::Error::custom("extension map exceeds plan JSON bounds"));
				}
				Ok(Map(entries))
			}
		}

		deserializer.deserialize_map(MapVisitor::<LIMIT>)
	}
}

struct Value<'a>(&'a [u8]);

impl Serialize for Value<'_> {
	fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		let mut decoder = Decoder::new(self.0);
		match decoder.datatype().map_err(S::Error::custom)? {
			Type::Null => serializer.serialize_unit(),
			Type::Bool => serializer.serialize_bool(decoder.bool().map_err(S::Error::custom)?),
			Type::U8
			| Type::U16
			| Type::U32
			| Type::U64
			| Type::I8
			| Type::I16
			| Type::I32
			| Type::I64
			| Type::Int => {
				let value = decoder.int().map_err(S::Error::custom)?;
				serializer.serialize_i128(i128::from(value))
			}
			Type::String => serializer.serialize_str(decoder.str().map_err(S::Error::custom)?),
			Type::Array => {
				let count = decoder
					.array()
					.map_err(S::Error::custom)?
					.ok_or_else(|| S::Error::custom("indefinite extension array"))?;
				let count = usize::try_from(count).map_err(S::Error::custom)?;
				let mut seq = serializer.serialize_seq(Some(count))?;
				for _ in 0..count {
					seq.serialize_element(&next_value(&mut decoder).map_err(S::Error::custom)?)?;
				}
				seq.end()
			}
			Type::Map => {
				let count = decoder
					.map()
					.map_err(S::Error::custom)?
					.ok_or_else(|| S::Error::custom("indefinite extension map"))?;
				let count = usize::try_from(count).map_err(S::Error::custom)?;
				let mut map = serializer.serialize_map(Some(count))?;
				for _ in 0..count {
					let key = decoder.str().map_err(S::Error::custom)?;
					let value = next_value(&mut decoder).map_err(S::Error::custom)?;
					map.serialize_entry(key, &value)?;
				}
				map.end()
			}
			_ => Err(S::Error::custom("unsupported extension")),
		}
	}
}

fn next_value<'a>(decoder: &mut Decoder<'a>) -> Result<Value<'a>, minicbor::decode::Error> {
	let start = decoder.position();
	decoder.skip()?;
	decoder
		.input()
		.get(start..decoder.position())
		.map(Value)
		.ok_or_else(|| minicbor::decode::Error::message("invalid extension span"))
}
