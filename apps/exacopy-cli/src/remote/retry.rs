//! Keeps the original grant, route and retry supervisor for a foreground capture.

use exacopy_sftp::SftpSourceError;
use exacopy_transfer::remote_capture::CaptureError;
use exacopy_transfer::remote_finalization::RemoteFinalizationOutcome;

use crate::assembly::linux::remote_download::{
	AttemptAdmission, ConnectedRemoteSource, ConnectingRemoteSource, DirectConnectError,
	RemoteDownloadFailure, RemoteDownloadRequest, RemoteRetryStamp, SourceInvocation,
	download_remote, download_retry,
};
use crate::remote_frontdoor::{ApprovedRoute, SshProfile};
use crate::remote_report::{RemoteFailureKind as Failure, RemoteJob, RemoteOutcome};

use super::{Interrupt, outcome};

pub(super) enum AttemptError {
	Foreground(Failure),
	Download(Box<RemoteDownloadFailure>),
}

impl AttemptError {
	fn download(error: RemoteDownloadFailure) -> Self {
		Self::Download(Box::new(error))
	}
}

pub(super) type Result = std::result::Result<RemoteFinalizationOutcome, AttemptError>;

pub(super) async fn attempt(
	connecting: ConnectingRemoteSource<'_>,
	ssh: &SshProfile,
	request: &RemoteDownloadRequest<'_>,
	interrupted: &Interrupt,
	admission: AttemptAdmission<'_>,
) -> Result {
	interrupted.check().map_err(AttemptError::Foreground)?;
	match &ssh.route {
		ApprovedRoute::EmbeddedWireGuard(_) => {
			#[cfg(feature = "experimental-ssh-wireguard")]
			{
				use crate::assembly::linux::remote_download::EmbeddedConnectError;

				connecting
					.with_embedded(ssh, admission, async |connected, admission| {
						transfer(connected, request, interrupted, admission).await
					})
					.await
					.map_err(|error| match error {
						EmbeddedConnectError::Native(error) => {
							AttemptError::download(RemoteDownloadFailure::ResumeAdmission(error))
						}
						error => AttemptError::Foreground(outcome::embedded_error(
							error,
							interrupted.cancelled(),
						)),
					})?
			}
			#[cfg(not(feature = "experimental-ssh-wireguard"))]
			Err(AttemptError::Foreground(Failure::Unsupported))
		}
		_ => {
			let connected = connecting
				.connect_direct(ssh, &admission)
				.await
				.map_err(|error| match error {
					DirectConnectError::Native(error) => {
						AttemptError::download(RemoteDownloadFailure::ResumeAdmission(error))
					}
					error => AttemptError::Foreground(outcome::connect_error(
						error,
						interrupted.cancelled(),
					)),
				})?;
			transfer(connected, request, interrupted, admission).await
		}
	}
}

async fn transfer(
	connected: ConnectedRemoteSource<'_>,
	request: &RemoteDownloadRequest<'_>,
	interrupted: &Interrupt,
	admission: AttemptAdmission<'_>,
) -> Result {
	interrupted
		.route(connected.cancellation_handle())
		.map_err(AttemptError::Foreground)?;
	match admission {
		AttemptAdmission::Initial(startup) => download_remote(request, connected, startup).await,
		AttemptAdmission::Retry(ready) => download_retry(request, connected, ready).await,
	}
	.map_err(AttemptError::download)
}

pub(super) async fn continue_capture(
	first: Result,
	had_job: bool,
	invocation: &SourceInvocation<'_>,
	ssh: &SshProfile,
	request: &RemoteDownloadRequest<'_>,
	interrupted: &Interrupt,
) -> Attempts {
	follow_stopped_reads(first, had_job, async |stamp| {
		invocation
			.backoff(stamp.previous_connection())
			.await
			.map_err(|error| {
				AttemptError::Foreground(outcome::start_error(&error, interrupted.cancelled()))
			})?;
		stamp
			.with_lease(request, async |ready| {
				interrupted.check().map_err(AttemptError::Foreground)?;
				let connecting = invocation.claim().map_err(|error| {
					AttemptError::Foreground(outcome::start_error(&error, interrupted.cancelled()))
				})?;
				attempt(
					connecting,
					ssh,
					request,
					interrupted,
					AttemptAdmission::Retry(ready),
				)
				.await
			})
			.await
			.map_err(AttemptError::download)?
	})
	.await
}

pub(super) struct Attempts {
	current: Result,
	had_job: bool,
	prior_read: Option<Box<RemoteDownloadFailure>>,
}

impl Attempts {
	pub(super) fn finish(self, job: RemoteJob, cancelled: bool) -> RemoteOutcome {
		let result = match self.current {
			Err(AttemptError::Foreground(code)) => {
				RemoteOutcome::failed(code, self.had_job.then_some(job))
			}
			Err(AttemptError::Download(error)) => {
				outcome::finish(Err(*error), job, cancelled, self.had_job)
			}
			Ok(outcome) => outcome::finish(Ok(outcome), job, cancelled, self.had_job),
		};
		// The public report projects just the active terminal outcome. Retain
		// the original typed read through this projection.
		drop(self.prior_read);
		result
	}
}

async fn follow_stopped_reads(
	mut current: Result,
	mut had_job: bool,
	mut retry: impl AsyncFnMut(Box<RemoteRetryStamp>) -> Result,
) -> Attempts {
	let mut prior_read = None;
	loop {
		let Err(AttemptError::Download(ref mut error)) = current else {
			break;
		};
		let Some(stamp) = take_retry(error) else {
			break;
		};
		had_job = true;
		let next = retry(stamp).await;
		if let Err(AttemptError::Download(previous)) = current {
			prior_read = Some(previous);
		}
		current = next;
	}
	Attempts {
		current,
		had_job,
		prior_read,
	}
}

fn take_retry(error: &mut RemoteDownloadFailure) -> Option<Box<RemoteRetryStamp>> {
	let RemoteDownloadFailure::Capture {
		cause,
		record_failure: None,
		route_failure: None,
		retry: proof @ Some(Ok(_)),
	} = error
	else {
		return None;
	};
	if !matches!(
		cause.as_ref(),
		CaptureError::Read {
			cause: SftpSourceError::ReadTimeout,
			..
		}
	) {
		return None;
	}
	proof.take()?.ok()
}

#[cfg(test)]
mod tests {
	use std::{cell::Cell, io};

	use exacopy_endpoint::IoError;
	use exacopy_platform::linux::StageError;
	use exacopy_transfer::remote_capture::StageStep;

	use exacopy_endpoint::connection_retry::{PermanentFailure, RetryBlock, RetryError};

	use super::*;
	use crate::assembly::linux::remote_download::{RemoteJobError, RemoteRouteCloseError};

	#[tokio::test]
	async fn forbidden_failures_never_call_the_redial_path() {
		let loss = || CaptureError::Read {
			offset: 5,
			cause: SftpSourceError::ReadTimeout,
		};
		let capture = |cause, record_failure, route_failure, retry| {
			AttemptError::download(RemoteDownloadFailure::Capture {
				cause: Box::new(cause),
				record_failure,
				route_failure,
				retry,
			})
		};
		let stage_write = |cause: StageError| CaptureError::Stage {
			step: StageStep::Write { offset: 5 },
			cause: cause.into(),
		};
		let forbidden = [
			capture(
				stage_write(StageError::Admission(io::Error::other("expired"))),
				None,
				None,
				None,
			),
			capture(
				stage_write(StageError::WriteOutcomeUnknown(IoError::System {
					offset: 6,
					source: io::Error::other("one byte confirmed"),
				})),
				None,
				None,
				None,
			),
			capture(loss(), None, None, None),
			capture(loss(), None, None, Some(Err(RemoteJobError::Attempt))),
			capture(
				loss(),
				None,
				Some(RemoteRouteCloseError::WorkerTimeout),
				None,
			),
			capture(loss(), Some(RemoteJobError::Stopped), None, None),
			capture(
				CaptureError::SourceFinish(SftpSourceError::ReadTimeout),
				None,
				None,
				None,
			),
			capture(
				CaptureError::Read {
					offset: 5,
					cause: SftpSourceError::Binding(RetryError::Blocked(RetryBlock::Permanent(
						PermanentFailure::RouteAuthorityRefused,
					))),
				},
				None,
				None,
				None,
			),
			AttemptError::download(RemoteDownloadFailure::ResumeAdmission(
				RemoteJobError::Conflict,
			)),
			AttemptError::download(RemoteDownloadFailure::Job(RemoteJobError::Stopped)),
			AttemptError::Foreground(Failure::Cancelled),
			AttemptError::Foreground(Failure::Authorization),
		];
		let calls = Cell::new(0);
		for error in forbidden {
			let outcome = follow_stopped_reads(Err(error), true, async |_| {
				calls.set(calls.get() + 1);
				Err(AttemptError::Foreground(Failure::Io))
			})
			.await;
			assert!(outcome.current.is_err());
			assert!(outcome.had_job);
			assert!(outcome.prior_read.is_none());
		}
		assert_eq!(calls.get(), 0);
	}
}
