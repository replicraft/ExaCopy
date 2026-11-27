use rustix::io::Errno;

use super::{ProcessCrashProfileError, mount_error};

#[test]
fn mount_errors_distinguish_unsupported_observation_from_io_failure() {
	for errno in [Errno::NOTSUP, Errno::NOSYS, Errno::INVAL] {
		assert!(
			matches!(
				mount_error(errno),
				ProcessCrashProfileError::UnsupportedMount
			),
			"mount observation error {errno:?}"
		);
	}

	let errno = Errno::IO;
	assert!(
		matches!(
			mount_error(errno),
			ProcessCrashProfileError::Io(error)
				if error.raw_os_error() == Some(errno.raw_os_error())
		),
		"a native mount I/O failure retains its original cause"
	);
}
