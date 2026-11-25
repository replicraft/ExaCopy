use std::num::NonZeroUsize;
use std::path::Path;

use exacopy_diff::linux::{self, MAX_SCRATCH_BYTES, Side};
use exacopy_platform::linux::{ReadRoot, SourceFile};

use crate::linux_path::{open_directory, split};
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
	let result = match workers {
		Some(workers) => linux::compare_parallel(&left, &right, &mut scratch, workers),
		None => linux::compare(&left, &right, &mut scratch),
	}
	.map_err(|error| Failure {
		code: ErrorCode::CompareInput,
		message: error.to_string(),
	})?;
	Ok(Outcome::from_comparison(result))
}

fn open(path: &Path, side: Side) -> Result<SourceFile, Failure> {
	let (parent, name) = split(path).map_err(|error| Failure {
		code: ErrorCode::InvalidPath,
		message: format!("{side} input path is invalid ({error})"),
	})?;
	let root = open_directory(parent).map_err(|error| Failure {
		code: ErrorCode::OpenInput,
		message: format!("could not open the {side} input directory ({error})"),
	})?;
	let root = ReadRoot::from_directory(root).map_err(|error| Failure {
		code: ErrorCode::OpenInput,
		message: format!("could not bind the {side} input directory ({error})"),
	})?;
	root.open_regular(name).map_err(|error| Failure {
		code: ErrorCode::OpenInput,
		message: format!("could not open the {side} input file ({error})"),
	})
}
