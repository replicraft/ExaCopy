use serde::{Deserialize, Deserializer, de};
use serde_json::value::RawValue;

pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
	let raw = <&RawValue>::deserialize(deserializer)?;
	exact_byte(raw.get())
		.ok_or_else(|| de::Error::custom("expected an unsigned integral JSON number"))
}

// RawValue has validated the JSON syntax. Read the decimal coefficient and
// scale without rounding, retaining only the digits needed for a u8.
fn exact_byte(text: &str) -> Option<u8> {
	if !text.as_bytes().first()?.is_ascii_digit() {
		return None;
	}
	let (mantissa, exponent) = text.split_once(['e', 'E']).unwrap_or((text, "0"));
	let exponent = bounded_exponent(exponent, text.len().checked_add(2)?)?;
	let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
	let digits = whole.bytes().chain(fraction.bytes());

	let Some(leading_zeros) = digits.clone().position(|byte| byte != b'0') else {
		return Some(0);
	};
	let trailing_zeros = digits.clone().rev().position(|byte| byte != b'0')?;
	let significant = whole
		.len()
		.checked_add(fraction.len())?
		.checked_sub(leading_zeros)?
		.checked_sub(trailing_zeros)?;
	// Trailing coefficient zeros cancel fractional scale or contribute to the
	// integer. A remaining fractional place would lose a nonzero digit.
	let scale = exponent
		.checked_add(isize::try_from(trailing_zeros).ok()?)?
		.checked_sub(isize::try_from(fraction.len()).ok()?)?;
	let zeroes = usize::try_from(scale).ok()?;
	if significant.checked_add(zeroes)? > 3 {
		return None;
	}
	digits
		.skip(leading_zeros)
		.take(significant)
		.chain(core::iter::repeat_n(b'0', zeroes))
		.try_fold(0_u8, |value, byte| {
			value.checked_mul(10)?.checked_add(byte.checked_sub(b'0')?)
		})
}

fn bounded_exponent(text: &str, limit: usize) -> Option<isize> {
	let negative = text.starts_with('-');
	let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
	let magnitude = digits.bytes().try_fold(0_usize, |value, byte| {
		let digit = usize::from(byte.checked_sub(b'0')?);
		let next = value.checked_mul(10)?.checked_add(digit)?;
		(next <= limit).then_some(next)
	})?;
	let magnitude = isize::try_from(magnitude).ok()?;
	if negative {
		magnitude.checked_neg()
	} else {
		Some(magnitude)
	}
}
