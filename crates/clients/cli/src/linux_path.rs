use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use exacopy_endpoint::{NameError, UnixComponent};
use exacopy_platform::linux::{DestinationRoot, StageError};
use rustix::fs::{self, Mode, OFlags};

pub(crate) fn split(path: &Path) -> Result<(&OsStr, UnixComponent<'_>), NameError> {
	let bytes = path.as_os_str().as_bytes();
	let (parent, name) = match bytes.iter().rposition(|byte| *byte == b'/') {
		None => (&b"."[..], bytes),
		Some(0) => (&b"/"[..], &bytes[1..]),
		Some(index) => (&bytes[..index], &bytes[index + 1..]),
	};
	Ok((OsStr::from_bytes(parent), UnixComponent::new(name)?))
}

pub(crate) fn open_directory(path: &OsStr) -> rustix::io::Result<File> {
	fs::open(
		path,
		OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
		Mode::empty(),
	)
	.map(File::from)
}

pub(crate) fn open_destination(path: &Path) -> Result<DestinationRoot, StageError> {
	DestinationRoot::from_directory(open_directory(path.as_os_str())?)
}
