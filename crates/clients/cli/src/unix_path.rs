use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use exacopy_endpoint::{NameError, UnixComponent};

pub(crate) fn split(path: &Path) -> Result<(&OsStr, UnixComponent<'_>), NameError> {
	let bytes = path.as_os_str().as_bytes();
	let (parent, name) = match bytes.iter().rposition(|byte| *byte == b'/') {
		None => (&b"."[..], bytes),
		Some(0) => (&b"/"[..], &bytes[1..]),
		Some(index) => (&bytes[..index], &bytes[index + 1..]),
	};
	Ok((OsStr::from_bytes(parent), UnixComponent::new(name)?))
}
