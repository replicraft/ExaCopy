use super::{RetainedPrefixRead, SyncedRetainedPrefix};

impl SyncedRetainedPrefix<'_, '_> {
	/// Actual native end immediately after the adopted-prefix barrier.
	#[must_use]
	pub const fn end(&self) -> u64 {
		self.end
	}

	/// Identifies the exact original retained reader, including its live lease guard.
	#[must_use]
	pub fn matches_reader(&self, expected: &RetainedPrefixRead<'_>) -> bool {
		std::ptr::eq(self.reader, expected)
	}
}

use std::ops::Range;

use super::{Phase, RetainedSuffixWriter, StageError};

/// Actual data-barrier observation while the original native writer is parked.
#[must_use]
pub struct SyncedSuffixRange<'writer, 'view, 'lease> {
	writer: &'writer RetainedSuffixWriter<'view, 'lease>,
	range: Range<u64>,
}

impl<'view, 'lease> RetainedSuffixWriter<'view, 'lease> {
	/// Stops all future mutations through this writer without removing evidence.
	pub fn stop(&mut self) {
		self.phase = Phase::Stopped;
	}

	/// Identifies the original native reader and live stage guard for this writer.
	#[must_use]
	pub fn matches_reader(&self, reader: &RetainedPrefixRead<'_>) -> bool {
		std::ptr::eq(self.reader, reader)
	}

	/// Borrows the currently synchronized range for the matching ledger append.
	///
	/// # Errors
	/// Refuses when the writer has no pending exact checkpoint or changed observations.
	pub fn checkpoint_proof(&self) -> Result<SyncedSuffixRange<'_, 'view, 'lease>, StageError> {
		let Phase::NeedsCheckpoint { start } = self.phase else {
			return Err(StageError::Unflushed);
		};
		self.check_current()?;
		Ok(SyncedSuffixRange {
			writer: self,
			range: start..self.stamp.len(),
		})
	}
}

impl SyncedSuffixRange<'_, '_, '_> {
	/// Returns the actual half-open range before any later write can occur.
	#[must_use]
	pub const fn range(&self) -> &Range<u64> {
		&self.range
	}

	pub(in crate::linux::recovery::writer) fn check_for(
		&self,
		expected: &RetainedPrefixRead<'_>,
	) -> Result<(), StageError> {
		if !std::ptr::eq(self.writer.reader, expected) {
			return Err(StageError::IdentityChanged);
		}
		self.writer.check_current()
	}
}
