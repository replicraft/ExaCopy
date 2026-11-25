//! Exact comparison for regular files held through managed macOS read capabilities.

use std::num::NonZeroUsize;

use exacopy_platform::macos::{ManagedReadError, ManagedRegularFile};

use crate::compare::parallel::compare_views_parallel;
use crate::compare::{ReadView, compare_views};
use crate::{CompareError, LiveComparison};

/// Compares live bytes through two held managed APFS file views.
///
/// Each file is revalidated before and after comparison. An equal result
/// covers the recorded extents, including sparse holes as logical zeros.
/// A difference reports unequal lengths or the first unequal byte. Ordinary
/// reads may update access times.
///
/// # Errors
/// An invalid length or scratch size, a failed observation check, or an
/// incomplete positional read makes the result inconclusive.
pub fn compare(
	left: &ManagedRegularFile<'_>,
	right: &ManagedRegularFile<'_>,
	scratch: &mut [u8],
) -> Result<LiveComparison, CompareError<ManagedReadError>> {
	compare_views(left, right, scratch)
}

/// Compares managed APFS file views using bounded, concurrent positioned reads.
///
/// A single worker runs on the calling thread. Multiple workers operate on
/// disjoint portions of the caller's scratch and all join before returning.
/// Scratch is bounded by [`crate::MAX_SCRATCH_BYTES`] and the worker ceiling
/// by [`crate::MAX_WORKERS`]. Observation and result semantics match [`compare`].
///
/// # Errors
/// Invalid input, an observation failure, a worker start failure or panic,
/// or a read failure before a first difference makes the result inconclusive.
pub fn compare_parallel(
	left: &ManagedRegularFile<'_>,
	right: &ManagedRegularFile<'_>,
	scratch: &mut [u8],
	workers: NonZeroUsize,
) -> Result<LiveComparison, CompareError<ManagedReadError>> {
	compare_views_parallel(left, right, scratch, workers)
}

impl ReadView for ManagedRegularFile<'_> {
	type Error = ManagedReadError;

	fn length(&self) -> u64 {
		self.length()
	}

	fn recheck_observation(&self) -> Result<(), ManagedReadError> {
		self.revalidate()
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), ManagedReadError> {
		self.read_exact_at(offset, buffer)
	}
}
