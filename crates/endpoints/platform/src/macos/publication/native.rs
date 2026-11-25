use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd};

/// Darwin <sys/stdio.h>. The pinned libc does not expose this flag.
const RENAME_NOFOLLOW_ANY: u32 = 0x0000_0010;

pub(super) fn rename_exclusively(
	from_directory: BorrowedFd<'_>,
	stage: &CStr,
	to_directory: BorrowedFd<'_>,
	target: &CStr,
) -> io::Result<()> {
	// SAFETY: Both directory descriptors stay borrowed, and both valid C
	// strings remain alive throughout the synchronous call. No pointer escapes.
	let status = unsafe {
		libc::renameatx_np(
			from_directory.as_raw_fd(),
			stage.as_ptr(),
			to_directory.as_raw_fd(),
			target.as_ptr(),
			libc::RENAME_EXCL | RENAME_NOFOLLOW_ANY,
		)
	};
	if status == 0 {
		Ok(())
	} else {
		Err(io::Error::last_os_error())
	}
}

#[cfg(test)]
mod tests;
