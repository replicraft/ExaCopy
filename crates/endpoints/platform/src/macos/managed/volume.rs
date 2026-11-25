use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd};

use super::acl::attribute_request;

const VOLUME_CAPS: u32 = libc::ATTR_VOL_CAPABILITIES;
const COMMON: u32 = libc::ATTR_CMN_RETURNED_ATTRS;
const ACL_AND_FLOCK: u32 = libc::VOL_CAP_INT_EXTENDED_SECURITY | libc::VOL_CAP_INT_FLOCK;
const ATTR_BITMAP_WORDS: usize = size_of::<libc::attribute_set_t>() / size_of::<u32>();
const CAPABILITY_WORDS: usize = size_of::<libc::vol_capabilities_attr_t>() / size_of::<u32>();
const START: usize = 1 + ATTR_BITMAP_WORDS;
const RESPONSE_WORDS: usize = START + CAPABILITY_WORDS;

pub(super) fn supports_managed_root(directory: BorrowedFd<'_>) -> io::Result<bool> {
	let mut request = attribute_request(COMMON);
	request.volattr = libc::ATTR_VOL_INFO | VOLUME_CAPS;
	let mut response = [0; RESPONSE_WORDS];
	// SAFETY: Darwin borrows a live descriptor and distinct, writable,
	// initialized request and four-byte-aligned response for this call. The
	// response size exactly matches the available storage and no pointer escapes.
	let status = unsafe {
		libc::fgetattrlist(
			directory.as_raw_fd(),
			&raw mut request as *mut _,
			response.as_mut_ptr().cast(),
			size_of_val(&response),
			libc::FSOPT_REPORT_FULLSIZE,
		)
	};
	if status != 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(supports_in_response(&response))
}

fn supports_in_response(response: &[u32; RESPONSE_WORDS]) -> bool {
	if usize::try_from(response[0]).ok() != Some(size_of_val(response))
		|| response[1] != COMMON
		|| response[2] != VOLUME_CAPS
		|| response[3..START].iter().any(|&word| word != 0)
	{
		return false;
	}
	let interfaces = START + libc::VOL_CAPABILITIES_INTERFACES;
	let format = START + libc::VOL_CAPABILITIES_FORMAT;
	let valid = CAPABILITY_WORDS / 2;
	response[interfaces] & response[interfaces + valid] & ACL_AND_FLOCK == ACL_AND_FLOCK
		&& response[format + valid] & libc::VOL_CAP_FMT_NO_PERMISSIONS != 0
		&& response[format] & libc::VOL_CAP_FMT_NO_PERMISSIONS == 0
}

#[test]
fn requires_reported_permission_acl_and_lock_support() {
	let mut exact = [0; RESPONSE_WORDS];
	exact[0] = size_of_val(&exact) as u32;
	exact[1] = COMMON;
	exact[2] = VOLUME_CAPS;
	let interfaces = START + libc::VOL_CAPABILITIES_INTERFACES;
	let format = START + libc::VOL_CAPABILITIES_FORMAT;
	let valid = CAPABILITY_WORDS / 2;
	exact[interfaces] = ACL_AND_FLOCK;
	exact[interfaces + valid] = ACL_AND_FLOCK;
	exact[format + valid] = libc::VOL_CAP_FMT_NO_PERMISSIONS;
	assert!(supports_in_response(&exact));
	for index in [0, 1, 2, interfaces, interfaces + valid, format + valid] {
		let mut uncertain = exact;
		uncertain[index] = 0;
		assert!(!supports_in_response(&uncertain));
	}
	exact[format] = libc::VOL_CAP_FMT_NO_PERMISSIONS;
	assert!(!supports_in_response(&exact));
}
