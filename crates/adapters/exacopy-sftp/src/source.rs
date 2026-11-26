use std::num::NonZeroUsize;

use exacopy_endpoint::connection_retry::{ConnectionBinding, RetryError};
use exacopy_endpoint::remote_source::{CapturedReadAt, SourceEpoch};
use exacopy_endpoint::{MAX_FILE_LENGTH, UnixComponent};
use exacopy_ssh::{FileObservation, MAX_READ_CHUNK_BYTES, ReadOnlySftp, RemotePositionedRead};

use crate::error::SftpSourceError;

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests;

mod pending;

pub use pending::{
	PendingSftpPathRequest, PendingSftpSource, PendingSftpSourceRequest, PendingSourceOwner,
	open_pending_path_source, open_pending_source, with_pending_source,
};

const MAX_WINDOW: NonZeroUsize =
	NonZeroUsize::new(1024 * 1024).expect("the fixed SFTP source window is nonzero");

/// The selected path and admitted generation for one held source pass.
pub struct SftpSourceRequest<'path> {
	/// Relative SFTP path represented by validated, raw Unix components.
	pub path: &'path [UnixComponent<'path>],
	/// Fresh source pass with the same identifier as the admitted binding.
	pub epoch: SourceEpoch,
	/// Binding assigned to the supplied authenticated session and source.
	pub binding: ConnectionBinding,
}

/// Runs an operation with one held source and consumes the supplied session.
///
/// The caller assigns the authenticated session to its exact connection binding.
/// The owner check is synchronous and is called around each awaited source
/// operation. It checks the current bound generation without holding a guard
/// across SFTP I/O. The scoped operation cannot return the source or session.
///
/// Observations are live server-reported metadata. The source still needs
/// [finish](CapturedReadAt::finish) to verify EOF and close the handle.
/// Existing SSH connection limits also apply while the callback performs
/// local work between source operations.
///
/// # Examples
///
/// The callback cannot return a reference to the held source.
///
/// ```compile_fail
/// use exacopy_sftp::{SftpSourceRequest, with_source};
/// use exacopy_ssh::ReadOnlySftp;
///
/// async fn escape(session: ReadOnlySftp, request: SftpSourceRequest<'_>) {
///     let _outside = with_source(session, request, |_| Ok(()), async |source| source).await;
/// }
/// ```
///
/// # Errors
/// Returns an admission, SFTP open, or extent error before running the callback.
/// The callback's result is returned as-is once the scope's source is retired.
pub async fn with_source<T, Check, Run>(
	mut session: ReadOnlySftp,
	request: SftpSourceRequest<'_>,
	check: Check,
	run: Run,
) -> Result<T, SftpSourceError>
where
	Check: FnMut(ConnectionBinding) -> Result<(), RetryError>,
	Run: for<'session, 'source> AsyncFnOnce(&'source mut SftpSource<'session, Check>) -> T,
{
	let mut source = SftpSource::open(&mut session, request, check).await?;
	Ok(run(&mut source).await)
}

/// Held SFTP implementation of the endpoint's live remote read capability.
///
/// Construct this source through [with_source]. No handle or session escapes
/// its owning scope, including after a stale terminal result.
pub struct SftpSource<'session, Check> {
	reader: Option<RemotePositionedRead<'session>>,
	epoch: SourceEpoch,
	binding: ConnectionBinding,
	observation: FileObservation,
	check: Check,
}

impl<'session, Check> SftpSource<'session, Check>
where
	Check: FnMut(ConnectionBinding) -> Result<(), RetryError>,
{
	async fn open(
		session: &'session mut ReadOnlySftp,
		request: SftpSourceRequest<'_>,
		mut check: Check,
	) -> Result<Self, SftpSourceError> {
		if request.binding.source_epoch() != request.epoch {
			return Err(SftpSourceError::Epoch);
		}
		check(request.binding).map_err(SftpSourceError::Binding)?;
		let opened = session.open_positioned(request.path).await;
		check(request.binding).map_err(SftpSourceError::Binding)?;
		let reader = opened?;
		let observation = reader.observation();
		if observation.length > MAX_FILE_LENGTH {
			return Err(SftpSourceError::Extent);
		}
		Ok(Self {
			reader: Some(reader),
			epoch: request.epoch,
			binding: request.binding,
			observation,
			check,
		})
	}

	fn check_binding(&mut self) -> Result<(), SftpSourceError> {
		(self.check)(self.binding).map_err(SftpSourceError::Binding)
	}

	fn take_current(&mut self) -> Result<RemotePositionedRead<'session>, SftpSourceError> {
		let reader = self.reader.take().ok_or(SftpSourceError::Closed)?;
		self.check_binding()?;
		Ok(reader)
	}

	fn match_observation(&self, observation: FileObservation) -> Result<(), SftpSourceError> {
		if observation != self.observation {
			return Err(SftpSourceError::Observation);
		}
		Ok(())
	}
}

impl<Check> CapturedReadAt for SftpSource<'_, Check>
where
	Check: FnMut(ConnectionBinding) -> Result<(), RetryError>,
{
	type Error = SftpSourceError;

	fn epoch(&self) -> SourceEpoch {
		self.epoch
	}

	fn length(&self) -> u64 {
		self.observation.length
	}

	fn max_window_bytes(&self) -> NonZeroUsize {
		MAX_WINDOW
	}

	async fn read_exact_at(&mut self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		let mut reader = self.take_current()?;
		let length = u64::try_from(bytes.len()).map_err(|_| SftpSourceError::Window)?;
		let end = offset.checked_add(length).ok_or(SftpSourceError::Window)?;
		if bytes.is_empty() || bytes.len() > MAX_WINDOW.get() || end > self.length() {
			return Err(SftpSourceError::Window);
		}
		let opened = reader.begin_window(offset, length).await;
		self.check_binding()?;
		let mut window = opened?;
		let mut remaining = bytes;
		while !remaining.is_empty() {
			let limit = remaining.len().min(MAX_READ_CHUNK_BYTES);
			let read = window.read_next(&mut remaining[..limit]).await;
			self.check_binding()?;
			let count = read?;
			if !(1..=limit).contains(&count) {
				return Err(SftpSourceError::Observation);
			}
			remaining = &mut remaining[count..];
		}
		let finished = window.finish().await;
		self.check_binding()?;
		let matched = finished?;
		self.match_observation(matched.file())?;
		if matched.offset() != offset || matched.length() != length {
			return Err(SftpSourceError::Observation);
		}
		self.reader = Some(reader);
		Ok(())
	}

	async fn recheck(&mut self) -> Result<(), Self::Error> {
		let mut reader = self.take_current()?;
		let observed = reader.recheck().await;
		self.check_binding()?;
		self.match_observation(observed?)?;
		self.reader = Some(reader);
		Ok(())
	}

	async fn finish(&mut self) -> Result<(), Self::Error> {
		let reader = self.take_current()?;
		let finished = reader.finish().await;
		self.check_binding()?;
		self.match_observation(finished?)
	}
}
