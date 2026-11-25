//! Bounded opaque extensions in the public Plan body.

use minicbor::Decoder;
use minicbor::data::Type;

use super::{MAX_PLAN_BODY_BYTES, PlanError};

const MAX_EXTENSION_FIELDS: u64 = 16;
const MAX_MAP_FIELDS: u64 = 64;
const MAX_ARRAY_ITEMS: u64 = 4_096;
const MAX_DEPTH: u8 = 32;
// The Plan body is the first container.
const EXTENSION_MAP_DEPTH: u8 = 2;

/// A validated canonical CBOR map of opaque public Plan extensions.
///
/// Supports null, booleans, integers in the CBOR base range, UTF-8 text,
/// definite arrays and definite text-keyed maps. The bytes are preserved
/// exactly. Their use as grants or executable policy is outside this type.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PlanExtensions<'body>(&'body [u8]);

impl<'body> PlanExtensions<'body> {
	/// Creates the empty extension map.
	#[must_use]
	pub const fn empty() -> Self {
		Self(&[0xa0])
	}

	/// Validates an exact canonical map for use in a Plan body.
	///
	/// # Errors
	/// Rejects malformed, noncanonical, oversized, and unsupported values.
	pub fn from_canonical_cbor(input: &'body [u8]) -> Result<Self, PlanError> {
		if input.len() > MAX_PLAN_BODY_BYTES {
			return Err(PlanError::Size);
		}
		let mut decoder = Decoder::new(input);
		let extensions = Self::read_from(&mut decoder)?;
		if decoder.position() != input.len() {
			return Err(PlanError::NonCanonical);
		}
		Ok(extensions)
	}

	/// Returns the original validated canonical map.
	#[must_use]
	pub const fn as_canonical_cbor(self) -> &'body [u8] {
		self.0
	}

	pub(super) fn read_from(decoder: &mut Decoder<'body>) -> Result<Self, PlanError> {
		let start = decoder.position();
		read_map(decoder, EXTENSION_MAP_DEPTH, true)?;
		Ok(Self(span(decoder, start)?))
	}
}

fn read_map(decoder: &mut Decoder<'_>, depth: u8, namespaced: bool) -> Result<(), PlanError> {
	if depth > MAX_DEPTH {
		return Err(PlanError::Bounds);
	}
	let start = decoder.position();
	let count = decoder.map()?.ok_or(PlanError::NonCanonical)?;
	let limit = if namespaced {
		MAX_EXTENSION_FIELDS
	} else {
		MAX_MAP_FIELDS
	};
	if count > limit {
		return Err(PlanError::Bounds);
	}
	preferred(decoder, start, head_len(count))?;
	let mut previous = None;
	for _ in 0..count {
		let key_start = decoder.position();
		let key = read_text(decoder)?;
		let encoded = span(decoder, key_start)?;
		if previous.is_some_and(|last| last >= encoded) {
			return Err(PlanError::NonCanonical);
		}
		if namespaced && !namespaced_key(key) {
			return Err(PlanError::Unsupported);
		}
		previous = Some(encoded);
		read_value(decoder, depth + 1)?;
	}
	Ok(())
}

fn read_array(decoder: &mut Decoder<'_>, depth: u8) -> Result<(), PlanError> {
	if depth > MAX_DEPTH {
		return Err(PlanError::Bounds);
	}
	let start = decoder.position();
	let count = decoder.array()?.ok_or(PlanError::NonCanonical)?;
	if count > MAX_ARRAY_ITEMS {
		return Err(PlanError::Bounds);
	}
	preferred(decoder, start, head_len(count))?;
	for _ in 0..count {
		read_value(decoder, depth + 1)?;
	}
	Ok(())
}

fn read_value(decoder: &mut Decoder<'_>, depth: u8) -> Result<(), PlanError> {
	match decoder.datatype()? {
		Type::Null => decoder.null()?,
		Type::Bool => {
			decoder.bool()?;
		}
		Type::U8
		| Type::U16
		| Type::U32
		| Type::U64
		| Type::I8
		| Type::I16
		| Type::I32
		| Type::I64
		| Type::Int => read_integer(decoder)?,
		Type::String => {
			read_text(decoder)?;
		}
		Type::Array => read_array(decoder, depth)?,
		Type::Map => read_map(decoder, depth, false)?,
		Type::StringIndef | Type::ArrayIndef | Type::MapIndef => {
			return Err(PlanError::NonCanonical);
		}
		_ => return Err(PlanError::Unsupported),
	}
	Ok(())
}

fn read_integer(decoder: &mut Decoder<'_>) -> Result<(), PlanError> {
	let start = decoder.position();
	let value = i128::from(decoder.int()?);
	let magnitude = if value < 0 { -1 - value } else { value };
	let magnitude = u64::try_from(magnitude).map_err(|_| PlanError::Bounds)?;
	preferred(decoder, start, head_len(magnitude))
}

fn read_text<'body>(decoder: &mut Decoder<'body>) -> Result<&'body str, PlanError> {
	let start = decoder.position();
	let value = decoder.str()?;
	preferred(decoder, start, head_len(value.len() as u64) + value.len())?;
	Ok(value)
}

fn span<'body>(decoder: &Decoder<'body>, start: usize) -> Result<&'body [u8], PlanError> {
	decoder
		.input()
		.get(start..decoder.position())
		.ok_or(PlanError::Malformed)
}

fn preferred(decoder: &Decoder<'_>, start: usize, bytes: usize) -> Result<(), PlanError> {
	if decoder.position().checked_sub(start) == Some(bytes) {
		Ok(())
	} else {
		Err(PlanError::NonCanonical)
	}
}

fn head_len(argument: u64) -> usize {
	match argument {
		0..=23 => 1,
		24..=0xff => 2,
		0x100..=0xffff => 3,
		0x1_0000..=0xffff_ffff => 5,
		_ => 9,
	}
}

fn namespaced_key(key: &str) -> bool {
	let valid_segment = |segment: &str| {
		!segment.is_empty()
			&& segment
				.bytes()
				.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
	};
	let mut segments = key.split(['.', '-']);
	segments.next().is_some_and(valid_segment)
		&& segments.next().is_some_and(valid_segment)
		&& segments.all(valid_segment)
}
