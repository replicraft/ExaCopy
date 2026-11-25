use core::{fmt, marker::PhantomData};
use std::io;

use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use super::{MAX_PLAN_JSON_BYTES, PlanJsonError};

const MAX_DEPTH: usize = 33;

// The public envelope adds one container outside the canonical body.
pub(super) fn check(input: &[u8]) -> Result<(), PlanJsonError> {
	if input.len() > MAX_PLAN_JSON_BYTES {
		return Err(PlanJsonError::Size);
	}
	let mut closings = [0; MAX_DEPTH];
	let mut depth = 0usize;
	let mut quoted = false;
	let mut escaped = false;
	for &byte in input {
		if quoted {
			if escaped {
				escaped = false;
			} else {
				match byte {
					b'\\' => escaped = true,
					b'"' => quoted = false,
					_ => {}
				}
			}
			continue;
		}
		match byte {
			b'"' => quoted = true,
			b'{' | b'[' => {
				let slot = closings.get_mut(depth).ok_or(PlanJsonError::Depth)?;
				*slot = if byte == b'{' { b'}' } else { b']' };
				depth += 1;
			}
			b'}' | b']' => {
				let previous = depth.checked_sub(1).ok_or(PlanJsonError::Json)?;
				if closings[previous] != byte {
					return Err(PlanJsonError::Json);
				}
				depth = previous;
			}
			_ => {}
		}
	}
	if quoted || depth != 0 {
		return Err(PlanJsonError::Json);
	}
	Ok(())
}

pub(super) fn to_json<T: Serialize>(value: &T) -> Result<Vec<u8>, PlanJsonError> {
	let mut writer = JsonBytes::default();
	serde_json::to_writer(&mut writer, value).map_err(|error| {
		if error.is_io() {
			PlanJsonError::Size
		} else {
			PlanJsonError::Json
		}
	})?;
	Ok(writer.0)
}

#[derive(Default)]
struct JsonBytes(Vec<u8>);

impl io::Write for JsonBytes {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		if bytes.len() > MAX_PLAN_JSON_BYTES - self.0.len() {
			return Err(io::Error::other("plan JSON size limit"));
		}
		self.0.extend_from_slice(bytes);
		Ok(bytes.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

/// Denies Serde's positional array representation of a named wire structure.
#[derive(Serialize)]
#[serde(transparent)]
pub(super) struct Object<T>(pub(super) T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		struct ObjectVisitor<T>(PhantomData<T>);

		impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
			type Value = Object<T>;

			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				f.write_str("a JSON object")
			}

			fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Self::Value, M::Error> {
				T::deserialize(de::value::MapAccessDeserializer::new(map)).map(Object)
			}
		}

		deserializer.deserialize_map(ObjectVisitor(PhantomData))
	}
}

/// Required JSON arrays retain at most the local cap of decoded elements.
#[derive(Serialize)]
#[serde(transparent)]
pub(super) struct Items<T, const LIMIT: usize>(pub(super) Vec<T>);

impl<'de, T: Deserialize<'de>, const LIMIT: usize> Deserialize<'de> for Items<T, LIMIT> {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		struct ItemsVisitor<T, const LIMIT: usize>(PhantomData<T>);

		impl<'de, T: Deserialize<'de>, const LIMIT: usize> Visitor<'de> for ItemsVisitor<T, LIMIT> {
			type Value = Items<T, LIMIT>;

			fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
				write!(f, "an array of at most {LIMIT} items")
			}

			fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
				let mut items = Vec::new();
				for _ in 0..LIMIT {
					let Some(item) = seq.next_element()? else {
						return Ok(Items(items));
					};
					items.push(item);
				}
				if seq.next_element::<IgnoredAny>()?.is_some() {
					return Err(de::Error::custom("array exceeds plan JSON bounds"));
				}
				Ok(Items(items))
			}
		}

		deserializer.deserialize_seq(ItemsVisitor(PhantomData))
	}
}

pub(super) fn nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
	deserializer: D,
) -> Result<Option<T>, D::Error> {
	Option::<T>::deserialize(deserializer)
}
