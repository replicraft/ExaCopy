use std::fmt::Display;

use exacopy_diff::{CompareError, LiveComparison, MAX_SCRATCH_BYTES};

use crate::report::{ErrorCode, Failure, Outcome};

pub(crate) fn compare<E: Display>(
	compare: impl FnOnce(&mut [u8]) -> Result<LiveComparison, CompareError<E>>,
) -> Result<Outcome, Failure> {
	let mut scratch = Vec::new();
	scratch
		.try_reserve_exact(MAX_SCRATCH_BYTES)
		.map_err(|_| Failure {
			code: ErrorCode::ResourceLimit,
			message: "could not allocate the comparison buffer".into(),
		})?;
	scratch.resize(MAX_SCRATCH_BYTES, 0);
	compare(&mut scratch)
		.map(Outcome::from_comparison)
		.map_err(|error| Failure {
			code: ErrorCode::CompareInput,
			message: error.to_string(),
		})
}
