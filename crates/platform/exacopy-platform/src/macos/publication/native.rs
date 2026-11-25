use std::ffi::CStr;
use std::io;
use std::os::fd::BorrowedFd;

use rustix::fs::{RenameFlags, renameat_with};

/// Darwin <sys/stdio.h>. The pinned rustix preserves OS flag bits without a named constant.
const RENAME_NOFOLLOW_ANY: RenameFlags = RenameFlags::from_bits_retain(0x0000_0010);

pub(in super::super) fn rename_exclusively(
	from_directory: BorrowedFd<'_>,
	stage: &CStr,
	to_directory: BorrowedFd<'_>,
	target: &CStr,
) -> io::Result<()> {
	renameat_with(
		from_directory,
		stage,
		to_directory,
		target,
		RenameFlags::NOREPLACE | RENAME_NOFOLLOW_ANY,
	)
	.map_err(Into::into)
}

#[cfg(test)]
mod tests;
