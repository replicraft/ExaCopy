//! Keeps the original grant, route and retry supervisor for a foreground capture.

use exacopy_sftp::SftpSourceError;
use exacopy_transfer::remote_capture::CaptureError;
use exacopy_transfer::remote_finalization::RemoteFinalizationOutcome;

#[cfg(feature = "experimental-ssh-wireguard")]
use crate::assembly::linux::remote_download::EmbeddedConnectError;
use crate::assembly::linux::remote_download::{
	AttemptAdmission, ConnectedRemoteSource, ConnectingRemoteSource, DirectConnectError,
	RemoteDownloadFailure, RemoteDownloadRequest, RemoteRetryStamp, RemoteRouteCloseError,
	SourceInvocation, download_remote, download_retry,
};
use crate::remote_frontdoor::{ApprovedRoute, SshProfile};
use crate::remote_report::{RemoteFailureKind as Failure, RemoteJob, RemoteOutcome};

use super::{Interrupt, outcome};

pub(super) enum AttemptError {
	Foreground(Failure),
	Download(Box<RemoteDownloadFailure>),
	#[cfg(feature = "experimental-ssh-wireguard")]
	EmbeddedRetirement {
		outcome: Box<Result>,
		cause: RemoteRouteCloseError,
	},
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
	let (result, retirement) = with_connection(
		connecting,
		ssh,
		interrupted,
		admission,
		async |connected, admission| transfer(connected, request, interrupted, admission).await,
	)
	.await?;
	#[cfg(feature = "experimental-ssh-wireguard")]
	let result = with_embedded_retirement(result, retirement);
	#[cfg(not(feature = "experimental-ssh-wireguard"))]
	debug_assert!(retirement.is_none());
	result
}

pub(super) async fn with_connection<'held, T>(
	connecting: ConnectingRemoteSource<'_>,
	ssh: &SshProfile,
	interrupted: &Interrupt,
	admission: AttemptAdmission<'held>,
	consume: impl for<'route> AsyncFnOnce(ConnectedRemoteSource<'route>, AttemptAdmission<'held>) -> T,
) -> std::result::Result<(T, Option<RemoteRouteCloseError>), AttemptError> {
	interrupted.check().map_err(AttemptError::Foreground)?;
	match &ssh.route {
		ApprovedRoute::EmbeddedWireGuard(_) => {
			#[cfg(feature = "experimental-ssh-wireguard")]
			{
				match connecting
					.with_embedded(ssh, admission, || interrupted.cancelled(), consume)
					.await
				{
					Ok(scoped) => Ok((scoped.outcome, scoped.retirement.err())),
					Err(failure) => {
						let error = embedded_connect_failure(
							failure.cause,
							failure
								.cancelled_at_refusal
								.unwrap_or_else(|| interrupted.cancelled()),
						);
						Err(match failure.route_failure {
							Some(cause) => AttemptError::EmbeddedRetirement {
								outcome: Box::new(Err(error)),
								cause,
							},
							None => error,
						})
					}
				}
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
			Ok((consume(connected, admission).await, None))
		}
	}
}

#[cfg(feature = "experimental-ssh-wireguard")]
fn embedded_connect_failure(error: EmbeddedConnectError, cancelled: bool) -> AttemptError {
	match error {
		EmbeddedConnectError::Native(error) => {
			AttemptError::download(RemoteDownloadFailure::ResumeAdmission(error))
		}
		error => AttemptError::Foreground(outcome::embedded_error(error, cancelled)),
	}
}

#[cfg(feature = "experimental-ssh-wireguard")]
fn with_embedded_retirement(
	outcome: Result,
	route_failure: Option<RemoteRouteCloseError>,
) -> Result {
	match route_failure {
		Some(cause) => Err(AttemptError::EmbeddedRetirement {
			outcome: Box::new(outcome),
			cause,
		}),
		None => outcome,
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
		#[cfg(feature = "experimental-verified-prefix-resume")]
		AttemptAdmission::Witnessed(_) => Err(RemoteDownloadFailure::ResumeAdmission(
			crate::assembly::linux::remote_download::RemoteJobError::Binding,
		)),
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
		let result = project(self.current, job, cancelled, self.had_job);
		// The public report projects just the active terminal outcome. Retain
		// the original typed read through this projection.
		drop(self.prior_read);
		result
	}
}

pub(super) fn project(
	current: Result,
	job: RemoteJob,
	cancelled: bool,
	had_job: bool,
) -> RemoteOutcome {
	match current {
		Err(AttemptError::Foreground(code)) => RemoteOutcome::failed(code, had_job.then_some(job)),
		Err(AttemptError::Download(error)) => outcome::finish(Err(*error), job, cancelled, had_job),
		#[cfg(feature = "experimental-ssh-wireguard")]
		Err(AttemptError::EmbeddedRetirement { outcome, cause }) => {
			project(*outcome, job, cancelled, had_job).with_unconfirmed_route_retirement(cause)
		}
		Ok(outcome) => outcome::finish(Ok(outcome), job, cancelled, had_job),
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
			cause: SftpSourceError::ReadTimeout | SftpSourceError::ReadTimeoutBinding(_),
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

	#[cfg(feature = "experimental-ssh-wireguard")]
	#[tokio::test]
	async fn unconfirmed_retirement_reports_the_primary_refusal_without_redial() {
		use std::path::PathBuf;

		use exacopy_journal::JournalJobId;
		use uuid::Uuid;

		use crate::args::Format;

		let id = Uuid::parse_str("018d0454-2082-7444-8f45-7c4617e17ea2").unwrap();
		for (cancelled, code, exit, message) in [
			(
				false,
				"E_AUTHORIZATION",
				8,
				"the selected remote download authority was refused (transport retirement unconfirmed)",
			),
			(
				true,
				"E_CANCELLED",
				10,
				"remote download was cancelled (transport retirement unconfirmed)",
			),
		] {
			let error = embedded_connect_failure(
				EmbeddedConnectError::Ssh(exacopy_ssh::Error::Authentication),
				cancelled,
			);
			let current =
				with_embedded_retirement(Err(error), Some(RemoteRouteCloseError::WorkerTimeout));
			let attempts = follow_stopped_reads(current, false, async |_| {
				panic!("an embedded refusal must never call the redial path")
			})
			.await;
			let result = attempts.finish(
				RemoteJob {
					id: JournalJobId::from_bytes(id.into_bytes()).unwrap(),
					directory: PathBuf::from(".exacopy-unused"),
				},
				true,
			);
			assert_eq!(result.exit_code(), exit);
			let mut json = Vec::new();
			result
				.write(Format::Json, &mut json, &mut Vec::new())
				.unwrap();
			let json: serde_json::Value = serde_json::from_slice(&json).unwrap();
			assert_eq!(json["schema_version"], "1.0");
			assert_eq!(json["result"], "failed");
			assert_eq!(json["publication"], "not_published");
			assert_eq!(
				json["error"],
				serde_json::json!({"code": code, "message": message}),
			);
			let mut human = Vec::new();
			result
				.write(Format::Human, &mut Vec::new(), &mut human)
				.unwrap();
			assert_eq!(
				String::from_utf8(human).unwrap(),
				format!("exacopy: {message}\n")
			);
		}
	}
}
