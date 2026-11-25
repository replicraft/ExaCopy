use std::os::fd::AsFd;

use rustix::fs;
use rustix::io::{self, Errno};

use super::ReadError;

pub use exacopy_endpoint::linux_staging::ExtendedAttributes;

// Linux's VFS caps the name list returned by flistxattr at 64 KiB.
const MAX_LINUX_XATTR_LIST: usize = 64 * 1024;

pub(in crate::linux) fn inspect(fd: impl AsFd) -> Result<ExtendedAttributes, ReadError> {
	classify(fs::flistxattr_query(fd))
}

fn classify(result: io::Result<usize>) -> Result<ExtendedAttributes, ReadError> {
	match result {
		Ok(0) => Ok(ExtendedAttributes::NoneVisible),
		Ok(length) if length <= MAX_LINUX_XATTR_LIST => Ok(ExtendedAttributes::Present),
		Ok(_) | Err(Errno::TOOBIG) => Err(ReadError::ExtendedAttributeListTooLarge),
		Err(Errno::NOTSUP | Errno::NOSYS) => Ok(ExtendedAttributes::Unsupported),
		Err(error) => Err(ReadError::ExtendedAttributesUnreadable(error.into())),
	}
}

#[cfg(test)]
mod tests {
	use rustix::io::Errno;

	use super::{ExtendedAttributes, MAX_LINUX_XATTR_LIST, ReadError, classify};

	#[test]
	fn unavailable_names_and_inaccessible_names_are_distinct_from_an_empty_list() {
		assert!(matches!(
			classify(Ok(0)),
			Ok(ExtendedAttributes::NoneVisible)
		));
		for errno in [Errno::NOTSUP, Errno::NOSYS] {
			assert!(matches!(
				classify(Err(errno)),
				Ok(ExtendedAttributes::Unsupported)
			));
		}
		assert!(matches!(
			classify(Err(Errno::ACCESS)),
			Err(ReadError::ExtendedAttributesUnreadable(error))
				if error.raw_os_error() == Some(Errno::ACCESS.raw_os_error())
		));
	}

	#[test]
	fn incomplete_oversize_lists_fail_closed() {
		assert!(matches!(
			classify(Ok(MAX_LINUX_XATTR_LIST)),
			Ok(ExtendedAttributes::Present)
		));
		for result in [Ok(MAX_LINUX_XATTR_LIST + 1), Err(Errno::TOOBIG)] {
			assert!(matches!(
				classify(result),
				Err(ReadError::ExtendedAttributeListTooLarge)
			));
		}
	}
}
