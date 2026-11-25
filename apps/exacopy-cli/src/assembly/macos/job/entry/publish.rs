use exacopy_transfer::macos::job::entry::publish::{AttemptFailure, PreparedEvidence};

use super::PreparedDarwinEntry;
use crate::assembly::macos::receipt::DarwinCopyReceipt;

mod error;
mod native;
#[cfg(test)]
mod tests;

pub(super) use native::NativePreparedCopy;
use native::NativeReceiptStore;

pub use error::{DarwinCopyError, DarwinCopyFailure};
pub use exacopy_transfer::macos::job::entry::publish::PublicationProgress;

impl<'entry> PreparedDarwinEntry<'entry> {
	/// Copies the bound source and exclusively publishes the verified private stage.
	///
	/// Synchronizes exact intent before requesting the model authorization.
	/// Success returns the receipt after the private receipt file and its journal
	/// commitment have both passed their barriers. Achieved durability is unconfirmed.
	///
	/// # Errors
	/// Refuses changed inputs, failed verification, an incumbent, or incomplete effects.
	/// The failure identifies the retained job and the last established publication boundary.
	pub fn copy_and_publish(
		&mut self,
		scratch: &mut [u8],
	) -> Result<DarwinCopyReceipt<'entry>, DarwinCopyError> {
		self.attempt
			.execute(
				PreparedEvidence {
					frame: &self.frame,
					source: self.preparation.preparation().source.identity(),
					plan: &self.plan,
				},
				self.journal,
				&NativeReceiptStore(self.job),
				scratch,
			)
			.map_err(|error| {
				let failure = match error {
					AttemptFailure::AlreadyAttempted => DarwinCopyFailure::AlreadyAttempted,
					AttemptFailure::Copy(failure) => failure.into(),
				};
				DarwinCopyError::new(self.job_name(), self.attempt.progress(), failure)
			})
	}
}
