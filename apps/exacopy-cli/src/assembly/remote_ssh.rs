//! Composes the held SFTP adapter with the private-stage capture engine.

use exacopy_endpoint::connection_retry::{ConnectionBinding, RetryError};
use exacopy_sftp::{SftpSourceError, SftpSourceRequest, with_source};
use exacopy_ssh::ReadOnlySftp;
use exacopy_transfer::remote_capture::{
	CaptureCheckpoints, CaptureError, CaptureResult, CheckpointStage, capture_live,
};

#[cfg(test)]
mod tests;

#[cfg(all(
	test,
	target_os = "linux",
	feature = "experimental-verified-prefix-resume"
))]
pub(super) use tests::{admitted_at, generated_source};

/// Captures an admitted SFTP source into an already owned private stage.
///
/// The application owns connection admission and the execution context for
/// synchronous destination work. The SFTP adapter owns the consumed session
/// during this pass. A long quiet local stage read-back can still exceed the
/// connection inactivity limit before terminal SFTP confirmation.
///
/// # Errors
/// Returns a source admission, private capture, or terminal verification error.
pub async fn capture_sftp<W, C>(
	session: ReadOnlySftp,
	request: SftpSourceRequest<'_>,
	check: impl FnMut(ConnectionBinding) -> Result<(), RetryError>,
	writer: W,
	checkpoints: &mut C,
	scratch: &mut [u8],
) -> CaptureResult<W::Closed, SftpSourceError, W::Error, C::Error>
where
	W: CheckpointStage,
	C: CaptureCheckpoints<W::Binding>,
{
	let epoch = request.epoch;
	with_source(session, request, check, async move |source| {
		capture_live(source, epoch, writer, checkpoints, scratch).await
	})
	.await
	.map_err(CaptureError::SourceObservation)?
}
