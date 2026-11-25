use std::fs::File;
use std::os::fd::IntoRawFd as _;

use super::StageError;

pub(super) fn close_writer(file: File) -> Result<(), StageError> {
	let fd = file.into_raw_fd();
	// SAFETY: The owned File transferred its only descriptor here. No borrow
	// is live and nothing else will attempt to close or reuse the raw number.
	unsafe { rustix::io::try_close(fd) }.map_err(|error| StageError::CloseWriter(error.into()))
}
