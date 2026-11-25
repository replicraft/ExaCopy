use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd as _;

use exacopy_endpoint::{MAX_UNIX_COMPONENT_BYTES, UnixComponent};

use super::acl::attribute_request;

const REQUESTED: u32 = libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_NAME;
const WORD: usize = size_of::<u32>();
const REFERENCE: usize = WORD + size_of::<libc::attribute_set_t>();
const PAYLOAD: usize = REFERENCE + size_of::<libc::attrreference_t>();
const MAX_NAME_BYTES: usize = MAX_UNIX_COMPONENT_BYTES + 1;
const BUFFER_BYTES: usize = (PAYLOAD + MAX_NAME_BYTES).next_multiple_of(WORD);

#[repr(C, align(4))]
struct AttributeBuffer([u8; BUFFER_BYTES]);

pub(super) fn matches(file: &File, name: UnixComponent<'_>) -> io::Result<bool> {
	let mut request = attribute_request(REQUESTED);
	let mut buffer = AttributeBuffer([0; BUFFER_BYTES]);
	// SAFETY: The descriptor stays open throughout the call. The request and
	// aligned writable buffer are initialized, distinct, and valid for the
	// exact byte count passed to the synchronous ABI.
	let result = unsafe {
		libc::fgetattrlist(
			file.as_raw_fd(),
			&raw mut request as *mut _,
			buffer.0.as_mut_ptr().cast(),
			buffer.0.len(),
			libc::FSOPT_REPORT_FULLSIZE,
		)
	};
	if result != 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(decode(&buffer.0) == Some(name.as_bytes()))
}

fn decode(buffer: &[u8]) -> Option<&[u8]> {
	let bytes = buffer.get(..usize::try_from(word(buffer, 0)?).ok()?)?;
	if word(bytes, WORD)? != REQUESTED || bytes.get(2 * WORD..REFERENCE)? != [0; 4 * WORD] {
		return None;
	}
	let offset = usize::try_from(word(bytes, REFERENCE)?).ok()?;
	let length = usize::try_from(word(bytes, REFERENCE + WORD)?).ok()?;
	if offset != size_of::<libc::attrreference_t>() || !(2..=MAX_NAME_BYTES).contains(&length) {
		return None;
	}
	let end = PAYLOAD.checked_add(length)?;
	CStr::from_bytes_with_nul(bytes.get(PAYLOAD..end)?)
		.ok()
		.map(CStr::to_bytes)
}

fn word(bytes: &[u8], offset: usize) -> Option<u32> {
	Some(u32::from_ne_bytes(
		bytes.get(offset..offset + WORD)?.try_into().ok()?,
	))
}
