use std::num::NonZeroUsize;

use exacopy_endpoint::connection_retry::RetryError;
use exacopy_endpoint::remote_source::{CapturedReadAt, SourceEpoch};
use exacopy_sftp::SftpSourceError;

/// Couples completed positive held reads to the application's retry scheduler.
pub(in crate::assembly::linux::remote_download) struct VerifiedReads<Source, Observe> {
	source: Source,
	observe: Observe,
}

impl<Source, Observe> VerifiedReads<Source, Observe> {
	pub(in crate::assembly::linux::remote_download) fn new(
		source: Source,
		observe: Observe,
	) -> Self {
		Self { source, observe }
	}
}

impl<Source, Observe> CapturedReadAt for VerifiedReads<Source, Observe>
where
	Source: CapturedReadAt<Error = SftpSourceError>,
	Observe: FnMut() -> Result<(), RetryError>,
{
	type Error = SftpSourceError;

	fn epoch(&self) -> SourceEpoch {
		self.source.epoch()
	}

	fn length(&self) -> u64 {
		self.source.length()
	}

	fn max_window_bytes(&self) -> NonZeroUsize {
		self.source.max_window_bytes()
	}

	async fn read_exact_at(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		self.source.read_exact_at(offset, bytes).await?;
		if !bytes.is_empty() {
			// The held SFTP window checked its complete range, unchanged
			// observations and binding before returning this positive result.
			(self.observe)().map_err(SftpSourceError::Binding)?;
		}
		Ok(())
	}

	async fn recheck(&mut self) -> Result<(), Self::Error> {
		self.source.recheck().await
	}

	async fn finish(&mut self) -> Result<(), Self::Error> {
		self.source.finish().await
	}
}

#[cfg(test)]
mod tests;
