use std::num::NonZeroUsize;
use std::path::Path;

use exacopy_diff::Side;
use exacopy_platform::windows::WindowsReadFile;

use crate::report::{ErrorCode, Failure, Outcome};

pub(crate) fn compare(left: &Path, right: &Path, workers: Option<NonZeroUsize>) -> Outcome {
	match compare_files(left, right, workers) {
		Ok(outcome) => outcome,
		Err(error) => Outcome::Inconclusive { error },
	}
}

fn compare_files(
	left: &Path,
	right: &Path,
	workers: Option<NonZeroUsize>,
) -> Result<Outcome, Failure> {
	let left = open_file(left, Side::Left)?;
	let right = open_file(right, Side::Right)?;
	crate::diff::compare(&left, &right, workers)
}

fn open_file(path: &Path, side: Side) -> Result<WindowsReadFile, Failure> {
	WindowsReadFile::open_absolute(path).map_err(|error| Failure {
		code: if error.is_invalid_path() {
			ErrorCode::InvalidPath
		} else {
			ErrorCode::OpenInput
		},
		message: format!("could not bind the {side} input file ({error})"),
	})
}
