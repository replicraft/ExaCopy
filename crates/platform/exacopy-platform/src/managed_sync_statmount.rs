//! Read-only Linux statmount binding for the experimental managed sync profile.

use std::io;
use std::mem::{offset_of, size_of};
use std::num::NonZeroU64;

// Linux x86-64 and AArch64 LP64 UAPI. libc 0.2.191 lacks this constant on both.
const SYS_STATMOUNT: libc::c_long = 457;
const MNT_ID_REQ_SIZE_VER0: u32 = 24;
pub(crate) const STATMOUNT_MNT_BASIC: u64 = 0x0000_0002;

#[repr(C)]
struct Request {
	size: u32,
	spare: u32,
	mount: u64,
	mask: u64,
}

// Linux statmount fixed prefix through mnt_attr. Only MNT_BASIC is requested,
// so the kernel copies at most the supplied prefix and emits no strings.
#[repr(C)]
#[derive(Default)]
struct Response {
	size: u32,
	_unused_options: u32,
	mask: u64,
	_unused_superblock: [u64; 3],
	unique: u64,
	_unused_parent_unique: u64,
	ordinary: u32,
	_unused_parent_ordinary: u32,
	attributes: u64,
}

const RESPONSE_BYTES: usize = size_of::<Response>();
pub(crate) const BASIC_PREFIX_BYTES: u32 = 72;

const _: () = {
	assert!(size_of::<Request>() == MNT_ID_REQ_SIZE_VER0 as usize);
	assert!(offset_of!(Request, mount) == 8);
	assert!(offset_of!(Request, mask) == 16);
	assert!(offset_of!(Response, mask) == 8);
	assert!(offset_of!(Response, unique) == 40);
	assert!(offset_of!(Response, ordinary) == 56);
	assert!(offset_of!(Response, attributes) == 64);
	assert!(offset_of!(Response, attributes) + size_of::<u64>() == RESPONSE_BYTES);
	assert!(RESPONSE_BYTES == BASIC_PREFIX_BYTES as usize);
};

pub(crate) struct MountAttributes {
	pub(crate) size: u32,
	pub(crate) mask: u64,
	pub(crate) unique: u64,
	pub(crate) ordinary: u32,
	pub(crate) attributes: u64,
}

#[allow(unsafe_code, reason = "single bounded read-only statmount syscall")]
pub(crate) fn query(unique: NonZeroU64) -> io::Result<MountAttributes> {
	let request = Request {
		size: MNT_ID_REQ_SIZE_VER0,
		spare: 0,
		mount: unique.get(),
		mask: STATMOUNT_MNT_BASIC,
	};
	let mut response = Response::default();

	// SAFETY: The C-layout request and response contain initialized integer
	// fields and remain alive for this synchronous syscall. The v0 size covers
	// exactly the input, the exclusive output has RESPONSE_BYTES writable
	// bytes, and flags zero select the read-only current-namespace query.
	let result = unsafe {
		libc::syscall(
			SYS_STATMOUNT,
			&raw const request,
			&raw mut response,
			RESPONSE_BYTES,
			0_u32,
		)
	};
	match result {
		0 => Ok(MountAttributes {
			size: response.size,
			mask: response.mask,
			unique: response.unique,
			ordinary: response.ordinary,
			attributes: response.attributes,
		}),
		-1 => Err(io::Error::last_os_error()),
		_ => Err(io::ErrorKind::Unsupported.into()),
	}
}
