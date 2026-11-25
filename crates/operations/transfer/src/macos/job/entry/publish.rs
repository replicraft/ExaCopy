use super::PreparedDarwinEntry;
use crate::macos::receipt::DarwinCopyReceipt;

mod capabilities;
mod engine;
mod error;
mod native;
#[cfg(test)]
mod tests;

use engine::PreparedEvidence;
use native::NativePreparedCopy;

pub use engine::PublicationProgress;
pub use error::{DarwinCopyError, DarwinCopyFailure};

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
		let mut progress = self.progress;
		let result = self
			.writer
			.take()
			.ok_or(DarwinCopyFailure::AlreadyAttempted)
			.and_then(|writer| {
				engine::execute(
					PreparedEvidence {
						frame: &self.frame,
						source: self.preparation.preparation().source.identity(),
						plan: &self.plan,
					},
					NativePreparedCopy::new(self.source, writer),
					self.journal,
					self.job,
					scratch,
					&mut progress,
				)
				.map_err(DarwinCopyFailure::from)
			});
		self.progress = progress;
		result.map_err(|failure| DarwinCopyError::new(self.job_name(), progress, failure))
	}
}
