use std::ffi::OsStr;
use std::fs::File;
use std::path::Path;

use exacopy_platform::linux::{DestinationRoot, StageError};
use rustix::fs::{self, Mode, OFlags};

pub(crate) use crate::unix_path::split;

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
