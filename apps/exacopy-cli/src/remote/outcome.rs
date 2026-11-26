use exacopy_sftp::SftpSourceError;
use exacopy_transfer::remote_capture::{CaptureError, StageStep};
use exacopy_transfer::remote_finalization::{
	FinalizationCause, FinalizationProgress as Progress, RemoteFinalizationOutcome,
};

use crate::assembly::linux::remote_download::{
	DirectConnectError, RemoteDownloadFailure, RemoteJobError,
};
use crate::remote_frontdoor::FrontdoorError;
use crate::remote_report::{
	RemoteFailureKind as Failure, RemoteJob, RemoteOutcome, RemotePublication,
};

use super::resume::startup_outcome;

pub(super) fn finish(
	transfer: Result<RemoteFinalizationOutcome, RemoteDownloadFailure>,
	job: RemoteJob,
	cancelled: bool,
	had_job: bool,
) -> RemoteOutcome {
	match transfer {
		Ok(RemoteFinalizationOutcome::PublishedWithOmissions(receipt)) => {
			RemoteOutcome::published(&receipt, job)
		}
		Ok(RemoteFinalizationOutcome::Conflict { .. }) => failed(Failure::Conflict, job),
		Err(error) => download_error(error, job, cancelled, had_job),
		_ => RemoteOutcome::recovery_required(RemotePublication::PublicationUncertain, job),
	}
}

pub(super) fn frontdoor_error(cause: &FrontdoorError) -> Failure {
	match cause {
		FrontdoorError::Protected(_) | FrontdoorError::Trust(_) | FrontdoorError::Authority => {
			Failure::Authorization
		}
		_ => Failure::InvalidRequest,
	}
}

pub(super) fn start_error(error: &RemoteDownloadFailure, cancelled: bool) -> Failure {
	match error {
		RemoteDownloadFailure::Job(RemoteJobError::Grant(_)) if cancelled => Failure::Cancelled,
		RemoteDownloadFailure::Job(RemoteJobError::Grant(_)) => Failure::Authorization,
		RemoteDownloadFailure::Job(RemoteJobError::UnsupportedRoute) => Failure::Unsupported,
		RemoteDownloadFailure::Source(cause) => source_error(cause, cancelled),
		_ => Failure::Io,
	}
}

pub(super) fn connect_error(error: DirectConnectError, cancelled: bool) -> Failure {
	match error {
		DirectConnectError::Authority => Failure::Authorization,
		DirectConnectError::Profile(error) => frontdoor_error(&error),
		DirectConnectError::Retry(_) if cancelled => Failure::Cancelled,
		DirectConnectError::Retry(_) => Failure::Authorization,
		DirectConnectError::Ssh(error) => ssh_error(&error),
		DirectConnectError::Timeout | DirectConnectError::Dial(_) if cancelled => {
			Failure::Cancelled
		}
		DirectConnectError::Timeout | DirectConnectError::Dial(_) => Failure::Io,
	}
}

#[cfg(feature = "experimental-ssh-wireguard")]
pub(super) fn embedded_error(
	error: crate::assembly::linux::remote_download::EmbeddedConnectError,
	cancelled: bool,
) -> Failure {
	use crate::assembly::linux::remote_download::EmbeddedConnectError as Error;

	match error {
		_ if cancelled => Failure::Cancelled,
		Error::Authority | Error::KeyProfile | Error::Retry(_) => Failure::Authorization,
		Error::Profile(error) => frontdoor_error(&error),
		Error::Mtu => Failure::InvalidRequest,
		Error::Ssh(error) => ssh_error(&error),
		Error::Entropy
		| Error::Timeout
		| Error::HandshakeBudget
		| Error::Udp(_)
		| Error::Peer(_)
		| Error::Tcp(_) => Failure::Io,
	}
}

fn download_error(
	error: RemoteDownloadFailure,
	job: RemoteJob,
	cancelled: bool,
	had_job: bool,
) -> RemoteOutcome {
	match error {
		RemoteDownloadFailure::Job(error) => job_error(error, job, cancelled),
		RemoteDownloadFailure::ResumeAdmission(error) => resume_admission_error(error, job),
		RemoteDownloadFailure::Attestation(_) => {
			RemoteOutcome::failed(Failure::Authorization, had_job.then_some(job))
		}
		RemoteDownloadFailure::Source(error) => {
			RemoteOutcome::failed(source_error(&error, cancelled), had_job.then_some(job))
		}
		RemoteDownloadFailure::Capture {
			cause,
			record_failure,
			route_failure,
		} => {
			if record_failure.is_some() || route_failure.is_some() {
				return RemoteOutcome::recovery_required(RemotePublication::NotPublished, job);
			}
			match *cause {
				CaptureError::SourceFinish(_)
				| CaptureError::Checkpoint { .. }
				| CaptureError::Stage {
					step: StageStep::SyncPrefix { .. } | StageStep::Close,
					..
				} => RemoteOutcome::recovery_required(RemotePublication::NotPublished, job),
				CaptureError::SourceObservation(error)
				| CaptureError::Read { cause: error, .. } => failed(source_error(&error, cancelled), job),
				CaptureError::Stage { .. } => failed(Failure::Io, job),
				_ => failed(Failure::Integrity, job),
			}
		}
		RemoteDownloadFailure::SourceRetirement { .. } => {
			RemoteOutcome::recovery_required(RemotePublication::NotPublished, job)
		}
		RemoteDownloadFailure::Finalization(error) => {
			if matches!(
				error.progress,
				Progress::BeforeIntent | Progress::SealedBeforeIntent
			) && matches!(error.cause, FinalizationCause::TargetOccupied)
			{
				return failed(Failure::Conflict, job);
			}
			if let Some(publication) = unresolved(error.progress, cancelled) {
				return RemoteOutcome::recovery_required(publication, job);
			}
			let failure = match error.cause {
				_ if cancelled => Failure::Cancelled,
				FinalizationCause::Authority(_) => Failure::Authorization,
				FinalizationCause::TargetUnknown => Failure::Io,
				_ => Failure::Integrity,
			};
			failed(failure, job)
		}
		RemoteDownloadFailure::CommittedReceiptReadback { .. } => {
			RemoteOutcome::recovery_required(RemotePublication::Published, job)
		}
	}
}

fn unresolved(progress: Progress, cancelled: bool) -> Option<RemotePublication> {
	match progress {
		Progress::BeforeIntent => None,
		Progress::SealedBeforeIntent if cancelled => None,
		Progress::SealedBeforeIntent | Progress::PrivateJournalUncertain => {
			Some(RemotePublication::NotPublished)
		}
		Progress::PublishedIncomplete => Some(RemotePublication::Published),
		_ => Some(RemotePublication::PublicationUncertain),
	}
}

fn resume_admission_error(error: RemoteJobError, job: RemoteJob) -> RemoteOutcome {
	match error {
		RemoteJobError::Conflict => failed(Failure::Conflict, job),
		RemoteJobError::Lifecycle { phase, issue, .. } => {
			startup_outcome(phase, issue.is_none(), &job).unwrap_or_else(|| {
				RemoteOutcome::recovery_required(RemotePublication::PublicationUncertain, job)
			})
		}
		_ => RemoteOutcome::recovery_required(RemotePublication::PublicationUncertain, job),
	}
}

fn job_error(error: RemoteJobError, job: RemoteJob, cancelled: bool) -> RemoteOutcome {
	use RemoteJobError as JobError;
	match error {
		JobError::Conflict => failed(Failure::Conflict, job),
		JobError::Lifecycle { phase, issue, .. } => startup_outcome(phase, issue.is_none(), &job)
			.unwrap_or_else(|| {
				RemoteOutcome::recovery_required(RemotePublication::NotPublished, job)
			}),
		JobError::Grant(_) if cancelled => failed(Failure::Cancelled, job),
		JobError::Grant(_)
		| JobError::Binding
		| JobError::Qualification(_)
		| JobError::Profile(_) => failed(Failure::Authorization, job),
		JobError::UnsupportedRoute | JobError::Metadata(_) => failed(Failure::Unsupported, job),
		JobError::Attempt | JobError::Read(_) | JobError::Format(_) => {
			failed(Failure::Integrity, job)
		}
		_ => RemoteOutcome::recovery_required(RemotePublication::NotPublished, job),
	}
}

fn source_error(error: &SftpSourceError, cancelled: bool) -> Failure {
	if cancelled {
		return Failure::Cancelled;
	}
	match error {
		SftpSourceError::Sftp(error) => ssh_error(error),
		SftpSourceError::Closed => Failure::Io,
		SftpSourceError::Binding(_) | SftpSourceError::ReadBinding { .. } => Failure::Authorization,
		_ => Failure::Integrity,
	}
}

fn ssh_error(error: &exacopy_ssh::Error) -> Failure {
	use exacopy_ssh::Error as Ssh;
	match error {
		Ssh::HostKey(_)
		| Ssh::HostCertificate
		| Ssh::Authentication
		| Ssh::KeyAuthentication
		| Ssh::Credential(_)
		| Ssh::Password
		| Ssh::KeyProfile => Failure::Authorization,
		_ => Failure::Io,
	}
}

fn failed(code: Failure, job: RemoteJob) -> RemoteOutcome {
	RemoteOutcome::failed(code, Some(job))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_busy_resume_handoff_reports_uncertain_publication_even_on_interrupt() {
		use std::path::PathBuf;

		use exacopy_journal::JournalJobId;
		use exacopy_platform::linux::StageError;
		use uuid::Uuid;

		let id = Uuid::parse_str("018d0454-2082-7444-8f45-7c4617e17ea2").unwrap();
		let job = RemoteJob {
			id: JournalJobId::from_bytes(id.into_bytes()).unwrap(),
			directory: PathBuf::from(".exacopy-018d0454-2082-7444-8f45-7c4617e17ea2"),
		};
		let result = finish(
			Err(RemoteDownloadFailure::ResumeAdmission(
				RemoteJobError::Native(StageError::JobBusy),
			)),
			job,
			true,
			true,
		);
		assert_eq!(result.exit_code(), 9);
		let mut stdout = Vec::new();
		result
			.write(crate::args::Format::Json, &mut stdout, &mut Vec::new())
			.unwrap();
		let report: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
		assert_eq!(report["publication"], "publication_uncertain");
	}

	#[test]
	fn late_interrupt_never_suppresses_unconfirmed_publication_or_confirmed_publish() {
		assert!(unresolved(Progress::BeforeIntent, true).is_none());
		assert!(matches!(
			unresolved(Progress::IntentMayBeRecorded, true),
			Some(RemotePublication::PublicationUncertain)
		));
		assert!(matches!(
			unresolved(Progress::PublicationUncertain, true),
			Some(RemotePublication::PublicationUncertain)
		));
		assert!(matches!(
			unresolved(Progress::PublishedIncomplete, true),
			Some(RemotePublication::Published)
		));
		assert!(matches!(
			unresolved(Progress::PrivateJournalUncertain, true),
			Some(RemotePublication::NotPublished)
		));
	}
}
