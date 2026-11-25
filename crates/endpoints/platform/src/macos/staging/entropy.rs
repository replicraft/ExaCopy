use std::io;

use super::identity::RANDOM_STAGE_ID_BYTES;

pub(super) fn fill_stage_entropy(bytes: &mut [u8; RANDOM_STAGE_ID_BYTES]) -> io::Result<()> {
	// SAFETY: Darwin receives the exact length of initialized, writable storage.
	// The exclusive borrow lasts through this synchronous call, and the kernel
	// does not retain the pointer. The supplied buffer fits the syscall limit.
	let status = unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) };
	if status == 0 {
		Ok(())
	} else {
		Err(io::Error::last_os_error())
	}
}
