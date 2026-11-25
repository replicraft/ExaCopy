use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd};

use exacopy_endpoint::UnixComponent;

use super::acl::attribute_request;

const REQUESTED: u32 = libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_FSID;
const OPTIONS: u32 = libc::FSOPT_REPORT_FULLSIZE | libc::FSOPT_RETURN_REALDEV;
const BITMAP_WORDS: usize = size_of::<libc::attribute_set_t>() / size_of::<u32>();
const FSID_WORDS: usize = size_of::<libc::fsid_t>() / size_of::<u32>();
const VALUE_START: usize = 1 + BITMAP_WORDS;
const WORDS: usize = VALUE_START + FSID_WORDS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PhysicalFsid([u32; 2]);

impl PhysicalFsid {
	pub(super) fn held(fd: BorrowedFd<'_>) -> io::Result<Option<Self>> {
		let mut request = attribute_request(REQUESTED);
		let mut output = [0; WORDS];
		// SAFETY: The descriptor remains borrowed throughout the call. The
		// attribute request and four-byte-aligned initialized output are distinct
		// writable stack values. Their addresses are valid for the ABI and are
		// not retained after the synchronous call.
		let status = unsafe {
			libc::fgetattrlist(
				fd.as_raw_fd(),
				&raw mut request as *mut _,
				output.as_mut_ptr().cast(),
				size_of_val(&output),
				OPTIONS,
			)
		};
		Self::decode_if_success(status, &output)
	}

	pub(super) fn named(
		directory: BorrowedFd<'_>,
		name: UnixComponent<'_>,
	) -> io::Result<Option<Self>> {
		let name = CString::new(name.as_bytes())?;
		let mut request = attribute_request(REQUESTED);
		let mut output = [0; WORDS];
		// SAFETY: The checked single component has owned, terminated C storage
		// for the duration of the synchronous call. The borrowed directory,
		// request and output meet the same requirements as the held query.
		let status = unsafe {
			libc::getattrlistat(
				directory.as_raw_fd(),
				name.as_ptr(),
				&raw mut request as *mut _,
				output.as_mut_ptr().cast(),
				size_of_val(&output),
				(OPTIONS | libc::FSOPT_NOFOLLOW).into(),
			)
		};
		Self::decode_if_success(status, &output)
	}

	fn decode_if_success(status: libc::c_int, output: &[u32; WORDS]) -> io::Result<Option<Self>> {
		if status != 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(Self::decode(output))
	}

	fn decode(output: &[u32; WORDS]) -> Option<Self> {
		if usize::try_from(output[0]).ok()? != size_of_val(output)
			|| output[1] != REQUESTED
			|| output[2..VALUE_START].iter().any(|&word| word != 0)
		{
			return None;
		}
		let ids: [u32; 2] = output[VALUE_START..].try_into().ok()?;
		(ids != [0; 2]).then_some(Self(ids))
	}
}

#[test]
fn physical_fsid_requires_complete_returned_attributes() {
	let valid = [32, REQUESTED, 0, 0, 0, 0, 1234, 26];
	assert_eq!(PhysicalFsid::decode(&valid), Some(PhysicalFsid([1234, 26])));
	for (index, value) in [(0, 24), (0, 40), (1, libc::ATTR_CMN_RETURNED_ATTRS), (4, 1)] {
		let mut malformed = valid;
		malformed[index] = value;
		assert_eq!(PhysicalFsid::decode(&malformed), None);
	}
	let mut zero = valid;
	zero[VALUE_START..].fill(0);
	assert_eq!(PhysicalFsid::decode(&zero), None);
}
