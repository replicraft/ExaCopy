use core::fmt;

/// Maximum length of one child name in the Windows baseline, in UTF-16 code units.
pub const MAX_WINDOWS_COMPONENT_UNITS: usize = 255;

const ASCII_SPACE: u16 = b' ' as u16;
const DOT: u16 = b'.' as u16;
const SUPERSCRIPT_ONE: u16 = 0x00B9;
const SUPERSCRIPT_TWO: u16 = 0x00B2;
const SUPERSCRIPT_THREE: u16 = 0x00B3;

const DEVICE_STEMS: [&[u8]; 6] = [b"CON", b"PRN", b"AUX", b"NUL", b"CONIN$", b"CONOUT$"];

/// A single child name for the Windows baseline, borrowing its original UTF-16 code units.
///
/// Admission is lexical. A held parent, no-follow resolution, object type and identity,
/// volume limits, and filesystem-specific name equivalence require native checks.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct WindowsComponent<'name>(&'name [u16]);

impl<'name> WindowsComponent<'name> {
	/// Validates a filename without allocating, decoding, or changing its code units.
	///
	/// # Errors
	/// Returns [`WindowsNameError`] when the name exceeds the baseline limit or has
	/// syntax reserved for paths, streams, device aliases, or ambiguous spellings.
	pub fn new(units: &'name [u16]) -> Result<Self, WindowsNameError> {
		let Some((first, last)) = units.first().zip(units.last()) else {
			return Err(WindowsNameError::Empty);
		};
		if units.len() > MAX_WINDOWS_COMPONENT_UNITS {
			return Err(WindowsNameError::TooLong);
		}
		if matches!(units, [DOT] | [DOT, DOT]) {
			return Err(WindowsNameError::DotComponent);
		}
		if *first == ASCII_SPACE || matches!(*last, ASCII_SPACE | DOT) {
			return Err(WindowsNameError::AmbiguousEdge);
		}
		for &unit in units {
			if let Ok(ascii) = u8::try_from(unit) {
				match ascii {
					0 => return Err(WindowsNameError::Nul),
					b'/' | b'\\' => return Err(WindowsNameError::Separator),
					b':' => return Err(WindowsNameError::Colon),
					1..=31 | b'<' | b'>' | b'"' | b'|' | b'?' | b'*' => {
						return Err(WindowsNameError::InvalidCharacter);
					}
					_ => {}
				}
			}
		}
		if reserved_device_name(units) {
			return Err(WindowsNameError::ReservedDevice);
		}
		Ok(Self(units))
	}

	/// Returns the original code units, without an appended terminator.
	#[must_use]
	pub const fn as_units(self) -> &'name [u16] {
		self.0
	}
}

impl fmt::Debug for WindowsComponent<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("WindowsComponent(<redacted>)")
	}
}

/// A name outside the Windows child component contract.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WindowsNameError {
	/// The component is empty.
	Empty,
	/// The component exceeds the baseline code-unit limit.
	TooLong,
	/// The component means the current or parent directory.
	DotComponent,
	/// The component starts with ASCII space or ends in ASCII space or period.
	AmbiguousEdge,
	/// The component contains an embedded NUL.
	Nul,
	/// The component contains a forward slash or backslash.
	Separator,
	/// The component contains a colon used in drive or stream syntax.
	Colon,
	/// The component contains a control character or Windows-reserved punctuation.
	InvalidCharacter,
	/// The component has a reserved device name stem.
	ReservedDevice,
}

impl fmt::Display for WindowsNameError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Empty => formatter.write_str("filename component is empty"),
			Self::TooLong => write!(
				formatter,
				"filename component exceeds {MAX_WINDOWS_COMPONENT_UNITS} UTF-16 code units"
			),
			Self::DotComponent => {
				formatter.write_str("filename component refers to the current or parent directory")
			}
			Self::AmbiguousEdge => formatter
				.write_str("filename component has an ambiguous leading or trailing character"),
			Self::Nul => formatter.write_str("filename component contains an embedded NUL"),
			Self::Separator => formatter.write_str("filename component contains a path separator"),
			Self::Colon => formatter.write_str("filename component contains a colon"),
			Self::InvalidCharacter => {
				formatter.write_str("filename component contains a Windows-reserved character")
			}
			Self::ReservedDevice => {
				formatter.write_str("filename component has a Windows device name stem")
			}
		}
	}
}

impl core::error::Error for WindowsNameError {}

fn reserved_device_name(units: &[u16]) -> bool {
	let mut stem = units.split(|unit| *unit == DOT).next().unwrap_or_default();
	// Refuse aliases with spaces between the reserved stem and the extension.
	while let Some((&ASCII_SPACE, rest)) = stem.split_last() {
		stem = rest;
	}
	if DEVICE_STEMS
		.iter()
		.any(|device| eq_ascii_stem(stem, device))
	{
		return true;
	}
	let Some((&digit, prefix)) = stem.split_last() else {
		return false;
	};
	(matches!(digit, SUPERSCRIPT_ONE | SUPERSCRIPT_TWO | SUPERSCRIPT_THREE)
		|| (u16::from(b'1')..=u16::from(b'9')).contains(&digit))
		&& (eq_ascii_stem(prefix, b"COM") || eq_ascii_stem(prefix, b"LPT"))
}

fn eq_ascii_stem(units: &[u16], stem: &[u8]) -> bool {
	units.len() == stem.len()
		&& units.iter().zip(stem).all(|(&unit, &letter)| {
			u8::try_from(unit).is_ok_and(|byte| byte.eq_ignore_ascii_case(&letter))
		})
}

#[cfg(test)]
mod tests;
