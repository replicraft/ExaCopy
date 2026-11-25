//! Additional shape checks for the supported SFTP v3 responses.

use std::collections::BTreeSet;

use exacopy_endpoint::MAX_UNIX_COMPONENT_BYTES;

use crate::error::Error;

// SFTP v3 response tags. The packet decoder still owns typed data decoding.
const VERSION: u8 = 2;
const STATUS: u8 = 101;
const HANDLE: u8 = 102;
const DATA: u8 = 103;
const NAME: u8 = 104;
const ATTRS: u8 = 105;

const MAX_PAGE_ENTRIES: u32 = 4096;
const MAX_LONGNAME_BYTES: usize = 4096;
const MAX_EXTENSIONS: usize = 128;
const MAX_EXTENSION_NAME_BYTES: usize = 255;
const MAX_EXTENSION_VALUE_BYTES: usize = 4096;

const ATTR_SIZE: u32 = 1;
const ATTR_UID_GID: u32 = 2;
const ATTR_PERMISSIONS: u32 = 4;
const ATTR_TIMES: u32 = 8;
const BASELINE_ATTR_FLAGS: u32 = ATTR_SIZE | ATTR_UID_GID | ATTR_PERMISSIONS | ATTR_TIMES;

pub(crate) fn check_response_shape(body: &[u8]) -> Result<(), Error> {
	let Some((&tag, payload)) = body.split_first() else {
		return Err(Error::Protocol);
	};
	let mut fields = Fields(payload);
	match tag {
		VERSION => check_version(&mut fields)?,
		NAME => check_names(&mut fields)?,
		ATTRS => {
			fields.u32()?;
			fields.attributes()?;
		}
		// Their lengths and fields are checked by the pinned packet decoder.
		STATUS | HANDLE | DATA => return Ok(()),
		_ => return Err(Error::Protocol),
	}
	if !fields.0.is_empty() {
		return Err(Error::Protocol);
	}
	Ok(())
}

fn check_version(fields: &mut Fields<'_>) -> Result<(), Error> {
	fields.u32()?;
	let mut names = BTreeSet::new();
	while !fields.0.is_empty() {
		if names.len() >= MAX_EXTENSIONS {
			return Err(Error::Limit);
		}
		let name = fields.string(MAX_EXTENSION_NAME_BYTES)?;
		if name.is_empty() || !name.iter().all(|byte| byte.is_ascii_graphic()) {
			return Err(Error::Protocol);
		}
		if !names.insert(name) {
			return Err(Error::Protocol);
		}
		fields.string(MAX_EXTENSION_VALUE_BYTES)?;
	}
	Ok(())
}

fn check_names(fields: &mut Fields<'_>) -> Result<(), Error> {
	fields.u32()?;
	let count = fields.u32()?;
	if count > MAX_PAGE_ENTRIES {
		return Err(Error::Limit);
	}
	for _ in 0..count {
		fields.string(MAX_UNIX_COMPONENT_BYTES)?;
		fields.string(MAX_LONGNAME_BYTES)?;
		fields.attributes()?;
	}
	Ok(())
}

struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
	fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
		let (value, rest) = self.0.split_at_checked(length).ok_or(Error::Protocol)?;
		self.0 = rest;
		Ok(value)
	}

	fn u32(&mut self) -> Result<u32, Error> {
		let bytes = self.take(4)?.try_into().map_err(|_| Error::Protocol)?;
		Ok(u32::from_be_bytes(bytes))
	}

	fn string(&mut self, max: usize) -> Result<&'a [u8], Error> {
		let length = self.u32()? as usize;
		if length > max {
			return Err(Error::Limit);
		}
		self.take(length)
	}

	fn attributes(&mut self) -> Result<(), Error> {
		let flags = self.u32()?;
		if flags & !BASELINE_ATTR_FLAGS != 0 {
			return Err(Error::UnsupportedSource);
		}
		// SFTP v3 fixed attribute widths. A length-checked slice is sufficient
		// here because the upstream codec reads the actual numeric values.
		let widths = [
			(ATTR_SIZE, 8),
			(ATTR_UID_GID, 8),
			(ATTR_PERMISSIONS, 4),
			(ATTR_TIMES, 8),
		];
		for (flag, width) in widths {
			if flags & flag != 0 {
				self.take(width)?;
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::{ATTRS, MAX_PAGE_ENTRIES, NAME, VERSION, check_response_shape};
	use crate::Error;

	#[test]
	fn validates_name_count_and_mandatory_attribute_word_before_decoding() {
		let mut name = vec![NAME];
		name.extend(5u32.to_be_bytes());
		name.extend(1u32.to_be_bytes());
		name.extend(1u32.to_be_bytes());
		name.push(255);
		name.extend(0u32.to_be_bytes());

		assert!(matches!(check_response_shape(&name), Err(Error::Protocol)));
		name.extend(0u32.to_be_bytes());
		assert!(check_response_shape(&name).is_ok());
		name[5..9].copy_from_slice(&(MAX_PAGE_ENTRIES + 1).to_be_bytes());
		assert!(matches!(check_response_shape(&name), Err(Error::Limit)));
	}

	#[test]
	fn rejects_unsupported_attribute_flags_before_lossy_decoding() {
		let mut attrs = vec![ATTRS];
		attrs.extend(9u32.to_be_bytes());
		assert!(matches!(check_response_shape(&attrs), Err(Error::Protocol)));
		attrs.extend(0x8000_0000u32.to_be_bytes());
		assert!(matches!(
			check_response_shape(&attrs),
			Err(Error::UnsupportedSource)
		));
	}

	#[test]
	fn rejects_duplicate_version_extension_names_before_map_decoding() {
		let mut version = vec![VERSION];
		version.extend(3u32.to_be_bytes());
		version.extend(1u32.to_be_bytes());
		version.push(b'n');
		version.extend(1u32.to_be_bytes());
		version.push(b'1');
		assert!(check_response_shape(&version).is_ok());
		version.extend(1u32.to_be_bytes());
		version.push(b'n');
		version.extend(1u32.to_be_bytes());
		version.push(b'2');
		assert!(matches!(
			check_response_shape(&version),
			Err(Error::Protocol)
		));
	}
}
