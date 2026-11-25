use std::fmt::Display;
use std::num::NonZeroUsize;

use exacopy_diff::MAX_SCRATCH_BYTES;
use exacopy_endpoint::ReadView;

use crate::report::{ErrorCode, Failure, Outcome};

pub(crate) fn compare<V>(
	left: &V,
	right: &V,
	workers: Option<NonZeroUsize>,
) -> Result<Outcome, Failure>
where
	V: ReadView + Sync,
	V::Error: Display + Send,
{
	let mut scratch = Vec::new();
	scratch
		.try_reserve_exact(MAX_SCRATCH_BYTES)
		.map_err(|_| Failure {
			code: ErrorCode::ResourceLimit,
			message: "could not allocate the comparison buffer".into(),
		})?;
	scratch.resize(MAX_SCRATCH_BYTES, 0);
	let comparison = match workers {
		Some(workers) => exacopy_diff::compare_parallel(left, right, &mut scratch, workers),
		None => exacopy_diff::compare(left, right, &mut scratch),
	};
	comparison
		.map(Outcome::from_comparison)
		.map_err(|error| Failure {
			code: ErrorCode::CompareInput,
			message: error.to_string(),
		})
}
