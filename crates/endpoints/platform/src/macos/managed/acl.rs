use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd};

const FIELD_BYTES: usize = size_of::<u32>();
const SECURITY_MASK: u32 = libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_EXTENDED_SECURITY;
const RETURNED_ATTRS: usize = FIELD_BYTES;
const REFERENCE: usize = RETURNED_ATTRS + size_of::<libc::attribute_set_t>();
const PAYLOAD: usize = REFERENCE + size_of::<libc::attrreference_t>();

// Darwin <sys/kauth.h>: magic, two 16-byte GUIDs, ACL count and ACL flags.
const FILESEC_MAGIC: u32 = 0x012c_c16d;
const GUID_BYTES: usize = 16;
const ENTRY_COUNT: usize = FIELD_BYTES + 2 * GUID_BYTES;
const ACL_FLAGS: usize = ENTRY_COUNT + FIELD_BYTES;
const EMPTY_FILESEC_BYTES: usize = ACL_FLAGS + FIELD_BYTES;

#[repr(C, align(4))]
struct AttributeBuffer([u8; PAYLOAD + EMPTY_FILESEC_BYTES]);

pub(super) fn has_explicit_empty_acl(fd: BorrowedFd<'_>) -> io::Result<bool> {
	Ok(is_explicit_empty_acl(&descriptor_security(fd)?.0))
}

// Use only for an exclusively created child on the positively admitted APFS volume.
pub(super) fn has_no_stage_acl_entries(fd: BorrowedFd<'_>) -> io::Result<bool> {
	let AttributeBuffer(response) = descriptor_security(fd)?;
	Ok(is_explicit_empty_acl(&response) || is_absent_acl(&response))
}

fn descriptor_security(fd: BorrowedFd<'_>) -> io::Result<AttributeBuffer> {
	let mut request = attribute_request(SECURITY_MASK);
	let mut buffer = AttributeBuffer([0; PAYLOAD + EMPTY_FILESEC_BYTES]);
	// SAFETY: The borrow keeps the descriptor live. The initialized attrlist and
	// four-byte-aligned initialized buffer are distinct, writable stack objects.
	// Darwin receives the full writable buffer length and retains neither pointer.
	let status = unsafe {
		libc::fgetattrlist(
			fd.as_raw_fd(),
			&raw mut request as *mut _,
			buffer.0.as_mut_ptr().cast(),
			buffer.0.len(),
			libc::FSOPT_REPORT_FULLSIZE,
		)
	};
	if status != 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(buffer)
}

pub(super) fn attribute_request(commonattr: u32) -> libc::attrlist {
	libc::attrlist {
		bitmapcount: libc::ATTR_BIT_MAP_COUNT,
		reserved: 0,
		commonattr,
		volattr: 0,
		dirattr: 0,
		fileattr: 0,
		forkattr: 0,
	}
}

fn is_explicit_empty_acl(response: &[u8]) -> bool {
	let Some(length) = field(response, 0).and_then(|value| usize::try_from(value).ok()) else {
		return false;
	};
	let Some(response) = response.get(..length) else {
		return false;
	};
	if field(response, RETURNED_ATTRS) != Some(SECURITY_MASK)
		|| response.get(RETURNED_ATTRS + FIELD_BYTES..REFERENCE) != Some(&[0; 4 * FIELD_BYTES])
	{
		return false;
	}
	// The sole reference is relative to its own first byte. With only this
	// variable attribute requested, an empty, unpadded payload follows it.
	if field(response, REFERENCE) != Some(size_of::<libc::attrreference_t>() as u32)
		|| field(response, REFERENCE + FIELD_BYTES) != Some(EMPTY_FILESEC_BYTES as u32)
		|| response.len() != PAYLOAD + EMPTY_FILESEC_BYTES
	{
		return false;
	}
	let payload = &response[PAYLOAD..];
	field(payload, 0) == Some(FILESEC_MAGIC)
		&& field(payload, ENTRY_COUNT) == Some(0)
		&& field(payload, ACL_FLAGS) == Some(0)
}

// APFS returns only ATTR_CMN_RETURNED_ATTRS for a fresh file with no ACL,
// along with a zeroed unused attrreference_t in this fixed-size response.
fn is_absent_acl(response: &[u8]) -> bool {
	field(response, 0) == Some(PAYLOAD as u32)
		&& field(response, RETURNED_ATTRS) == Some(libc::ATTR_CMN_RETURNED_ATTRS)
		&& response
			.get(RETURNED_ATTRS + FIELD_BYTES..PAYLOAD)
			.is_some_and(|fields| fields.iter().all(|&byte| byte == 0))
}

fn field(bytes: &[u8], offset: usize) -> Option<u32> {
	let value = bytes.get(offset..offset + FIELD_BYTES)?.try_into().ok()?;
	Some(u32::from_ne_bytes(value))
}

// Test setup uses only a freshly created synthetic directory descriptor.
#[cfg(test)]
pub(super) fn set_fixture_empty_acl(fd: BorrowedFd<'_>) -> io::Result<()> {
	const SET_PAYLOAD: usize = size_of::<libc::attrreference_t>();
	let mut request = attribute_request(libc::ATTR_CMN_EXTENDED_SECURITY);
	let mut buffer = AttributeBuffer([0; PAYLOAD + EMPTY_FILESEC_BYTES]);
	write_field(&mut buffer.0, 0, SET_PAYLOAD as u32);
	write_field(&mut buffer.0, FIELD_BYTES, EMPTY_FILESEC_BYTES as u32);
	write_field(&mut buffer.0, SET_PAYLOAD, FILESEC_MAGIC);
	// SAFETY: fd is held throughout the call. The aligned buffer and attribute
	// request are initialized and distinct. The one relative payload lies
	// entirely within the supplied length, and Darwin retains neither pointer.
	let status = unsafe {
		libc::fsetattrlist(
			fd.as_raw_fd(),
			&raw mut request as *mut _,
			buffer.0.as_mut_ptr().cast(),
			SET_PAYLOAD + EMPTY_FILESEC_BYTES,
			0,
		)
	};
	if status != 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(())
}

#[cfg(test)]
fn write_field(bytes: &mut [u8], offset: usize, value: u32) {
	bytes[offset..offset + FIELD_BYTES].copy_from_slice(&value.to_ne_bytes());
}

#[test]
fn rejects_uncertain_acl_payloads() {
	let mut valid = [0; PAYLOAD + EMPTY_FILESEC_BYTES];
	let length = valid.len() as u32;
	write_field(&mut valid, 0, length);
	write_field(&mut valid, RETURNED_ATTRS, SECURITY_MASK);
	write_field(
		&mut valid,
		REFERENCE,
		size_of::<libc::attrreference_t>() as u32,
	);
	write_field(
		&mut valid,
		REFERENCE + FIELD_BYTES,
		EMPTY_FILESEC_BYTES as u32,
	);
	write_field(&mut valid, PAYLOAD, FILESEC_MAGIC);
	assert!(is_explicit_empty_acl(&valid));
	for (offset, value) in [
		(0, length + 1),
		(0, length - 1),
		(RETURNED_ATTRS, libc::ATTR_CMN_RETURNED_ATTRS),
		(RETURNED_ATTRS + FIELD_BYTES, 1),
		(REFERENCE, u32::MAX),
		(REFERENCE, 0),
		(REFERENCE + FIELD_BYTES, 0),
		(PAYLOAD, 0),
		(PAYLOAD + ENTRY_COUNT, 1),
		(PAYLOAD + ENTRY_COUNT, u32::MAX),
		(PAYLOAD + ACL_FLAGS, 1),
	] {
		let mut uncertain = valid;
		write_field(&mut uncertain, offset, value);
		assert!(
			!is_explicit_empty_acl(&uncertain),
			"field {offset}, value {value}"
		);
	}
	for length in 0..valid.len() {
		assert!(
			!is_explicit_empty_acl(&valid[..length]),
			"truncated at {length}"
		);
	}
}

#[test]
fn fresh_stage_acl_absence_requires_the_exact_apfs_response() {
	let mut absent = [0; PAYLOAD + EMPTY_FILESEC_BYTES];
	write_field(&mut absent, 0, PAYLOAD as u32);
	write_field(&mut absent, RETURNED_ATTRS, libc::ATTR_CMN_RETURNED_ATTRS);
	assert!(is_absent_acl(&absent));
	assert!(!is_explicit_empty_acl(&absent));
	for (field, value) in [
		(0, (PAYLOAD - FIELD_BYTES) as u32),
		(0, (PAYLOAD + FIELD_BYTES) as u32),
		(RETURNED_ATTRS, SECURITY_MASK),
		(RETURNED_ATTRS + FIELD_BYTES, 1),
		(REFERENCE, 1),
		(REFERENCE + FIELD_BYTES, 1),
	] {
		let mut malformed = absent;
		write_field(&mut malformed, field, value);
		assert!(
			!is_absent_acl(&malformed),
			"accepted uncertain field {field}"
		);
	}
	assert!(!is_absent_acl(&absent[..PAYLOAD - 1]));
}
