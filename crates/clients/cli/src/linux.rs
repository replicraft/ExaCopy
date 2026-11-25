use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use exacopy_diff::linux::{MAX_SCRATCH_BYTES, Side};
use exacopy_endpoint::UnixComponent;
use exacopy_platform::linux::{ReadRoot, SourceFile};
use rustix::fs::{self, Mode, OFlags};

use crate::report::{ErrorCode, Failure, Outcome};

pub(crate) fn compare(left: &Path, right: &Path) -> Outcome {
	match compare_files(left, right) {
		Ok(outcome) => outcome,
		Err(error) => Outcome::Inconclusive { error },
	}
}

fn compare_files(left: &Path, right: &Path) -> Result<Outcome, Failure> {
	let left = open(left, Side::Left)?;
	let right = open(right, Side::Right)?;
	let mut scratch = Vec::new();
	scratch
		.try_reserve_exact(MAX_SCRATCH_BYTES)
		.map_err(|_| Failure {
			code: ErrorCode::ResourceLimit,
			message: "could not allocate the comparison buffer".into(),
		})?;
	scratch.resize(MAX_SCRATCH_BYTES, 0);
	let result =
		exacopy_diff::linux::compare(&left, &right, &mut scratch).map_err(|error| Failure {
			code: ErrorCode::CompareInput,
			message: error.to_string(),
		})?;
	Ok(Outcome::from_comparison(result))
}

fn open(path: &Path, side: Side) -> Result<SourceFile, Failure> {
	let bytes = path.as_os_str().as_bytes();
	let (parent, name) = match bytes.iter().rposition(|byte| *byte == b'/') {
		None => (&b"."[..], bytes),
		Some(0) => (&b"/"[..], &bytes[1..]),
		Some(index) => (&bytes[..index], &bytes[index + 1..]),
	};
	let name = UnixComponent::new(name).map_err(|error| Failure {
		code: ErrorCode::InvalidPath,
		message: format!("{side} input path is invalid ({error})"),
	})?;
	let root = fs::open(
		OsStr::from_bytes(parent),
		OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
		Mode::empty(),
	)
	.map_err(|error| Failure {
		code: ErrorCode::OpenInput,
		message: format!("could not open the {side} input directory ({error})"),
	})?;
	let root = ReadRoot::from_directory(File::from(root)).map_err(|error| Failure {
		code: ErrorCode::OpenInput,
		message: format!("could not bind the {side} input directory ({error})"),
	})?;
	root.open_regular(name).map_err(|error| Failure {
		code: ErrorCode::OpenInput,
		message: format!("could not open the {side} input file ({error})"),
	})
}
