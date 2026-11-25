use super::{ManifestError, ManifestInvalid};

const MAX_NESTING: usize = 32;

// Bound recursion before Serde processes even an unsupported, ignored value.
// Serde remains responsible for JSON syntax, types and duplicate known fields.
pub(super) fn check(input: &[u8]) -> Result<(), ManifestError> {
	let mut closings = [0; MAX_NESTING];
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
				let slot = closings.get_mut(depth).ok_or(ManifestInvalid::Depth)?;
				*slot = if byte == b'{' { b'}' } else { b']' };
				depth = depth.checked_add(1).ok_or(ManifestInvalid::Depth)?;
			}
			b'}' | b']' => {
				let previous = depth.checked_sub(1).ok_or(ManifestInvalid::Json)?;
				if closings[previous] != byte {
					return Err(ManifestInvalid::Json.into());
				}
				depth = previous;
			}
			_ => {}
		}
	}
	if quoted || depth != 0 {
		return Err(ManifestInvalid::Json.into());
	}
	Ok(())
}
