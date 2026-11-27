//! Protected successful CLI report selection for read-only witnessed inspection.

use std::path::Path;

use exacopy_platform::read_protected_snapshot_into;

use crate::assembly::linux::ArchivedWitnessedSelection;

mod codec;
#[cfg(test)]
mod tests;

pub(crate) use codec::{decode, report_selection};

/// Selection and reported lengths for independent inspection.
pub(crate) struct ArchivedWitnessSelection {
	pub(crate) selection: ArchivedWitnessedSelection,
	pub(crate) receipt_length: usize,
	pub(crate) stream_length: u64,
}

/// Snapshot protection or report validation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArchiveError {
	Snapshot,
	Format,
}

// Includes JSON escaping and the hex projection of the native path.
const MAX_REPORT_BYTES: usize = 64 * 1024;

/// Reads one protected archive selection, independently of any job or journal.
///
/// Select a report retained independently from a trusted foreground invocation.
/// Snapshot protection and this codec alone cannot authenticate its producer.
pub(crate) fn load(path: &Path) -> Result<ArchivedWitnessSelection, ArchiveError> {
	let mut bytes = vec![0; MAX_REPORT_BYTES];
	let mut readback = [0; 1024];
	let length = read_protected_snapshot_into(path, &mut bytes, &mut readback)
		.map_err(|_| ArchiveError::Snapshot)?;
	decode(&bytes[..length])
}
