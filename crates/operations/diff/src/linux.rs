//! Exact comparison for regular storage files opened through Linux read capabilities.

use std::num::NonZeroUsize;

use exacopy_platform::linux::{ReadError, SourceFile};

use crate::compare::parallel::compare_views_parallel;
use crate::compare::{ReadView, compare_views};

pub use crate::compare::error::{CompareError, Side};
pub use crate::compare::parallel::MAX_WORKERS;
pub use crate::compare::{Difference, LiveComparison, MAX_SCRATCH_BYTES};

/// Compare live bytes from two held regular storage files.
///
/// Each filesystem must report the logical stream's length when opening the
/// file. An equal result covers all bytes in those recorded extents, including
/// sparse holes as logical zeros. A difference reports unequal lengths or the
/// first unequal byte. The scratch buffer is split between the two reads and
/// may be empty for empty files or unequal lengths. At most [`MAX_SCRATCH_BYTES`]
/// total scratch bytes are accepted.
///
/// The recorded metadata and logical end of each file are rechecked around
/// the comparison.
/// Observation checks can detect some concurrent edits. Both the result and its
/// length or offset describe live observations through the held descriptors.
/// Ordinary reads may update access times.
///
/// # Errors
/// An invalid length or scratch size, a failed observation check, or an
/// incomplete positional read makes the result inconclusive.
pub fn compare(
	left: &SourceFile,
	right: &SourceFile,
	scratch: &mut [u8],
) -> Result<LiveComparison, CompareError<ReadError>> {
	compare_views(left, right, scratch)
}

/// Compare held live file views using bounded, concurrent positioned reads.
///
/// The caller supplies at most [`MAX_SCRATCH_BYTES`] of scratch for the entire
/// comparison and a worker ceiling of at most [`MAX_WORKERS`]. Each worker uses
/// one disjoint logical range and at least two of the supplied scratch bytes.
/// A one-worker comparison runs on the calling thread. All started workers
/// join before the comparison returns. Observation checks and result semantics
/// match [`compare`]; reads past the first difference can occur concurrently.
///
/// # Errors
/// Invalid input, an observation failure, a worker start failure or panic,
/// or a read failure before a first difference makes the result inconclusive.
pub fn compare_parallel(
	left: &SourceFile,
	right: &SourceFile,
	scratch: &mut [u8],
	workers: NonZeroUsize,
) -> Result<LiveComparison, CompareError<ReadError>> {
	compare_views_parallel(left, right, scratch, workers)
}

impl ReadView for SourceFile {
	type Error = ReadError;

	fn length(&self) -> u64 {
		self.len()
	}

	fn recheck_observation(&self) -> Result<(), ReadError> {
		self.recheck_observation()?;
		self.check_logical_eof()
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), ReadError> {
		self.read_exact_at(offset, buffer)
	}
}
