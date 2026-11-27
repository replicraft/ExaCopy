//! Application-only execution of one explicitly admitted agentless SFTP attempt.

use std::fmt;
use std::path::Path;

use exacopy_endpoint::linux_remote_qualification::RemoteDestinationQualification;
use exacopy_journal::remote_download::qualification::{
	RemoteQualificationError, RemoteQualificationScope, RemoteQualificationTrust,
	verify_remote_destination_qualification,
};
use exacopy_journal::remote_download::{RemoteDownloadScope, RemoteUncertainBoundary};
use exacopy_journal::{JournalJobId, OwnerTimestamp, OwnerToken};
use exacopy_platform::linux::{DestinationRoot, RecoveryReadLease, observe_remote_destination};
use exacopy_sftp::SftpSourceError;
use exacopy_transfer::remote_capture::{CaptureError, StageStep};
use exacopy_transfer::remote_finalization::{CommittedRemoteReceipt, FinalizationFailure};
use exacopy_transfer::remote_metadata::ApprovedSftpMetadata;

use crate::profile::LocalProfile;

pub(crate) use super::remote_journal::Error as RemoteJobError;
use super::remote_journal::Error;
use super::remote_stage::{NativeCaptureStageError, StageFinalizationError};

mod authority;
#[cfg(test)]
pub(in crate::assembly::linux) use authority::WitnessDeadline;
mod build;
mod capture;
pub(crate) use capture::{download_remote, download_retry};
mod retry;
mod source;
use authority::EffectAuthority;
pub use authority::RemoteGrant;
pub(super) use authority::native_authority;
pub use build::measure_running_executable;
pub(crate) use retry::ReadyRetry;
pub use retry::{RemoteRetryLease, RemoteRetryStamp};
#[cfg(test)]
pub(in crate::assembly::linux) use source::BoundRouteRetirement;
#[cfg(test)]
pub(in crate::assembly::linux) use source::RetiredBoundRoute;

pub(crate) use source::DirectConnectError;
#[cfg(feature = "experimental-ssh-wireguard")]
pub(crate) use source::EmbeddedConnectError;
pub(crate) use source::SourceInvocation;
pub use source::{
	ConnectedRemoteSource, ConnectingRemoteSource, CurrentEmbeddedStream,
	EmbeddedStreamObservation, RemoteRouteCloseError, RemoteRoutePeer,
};

/// Explicit selection of a fresh or retained private job.
#[derive(Clone, Copy, Debug)]
pub enum RemoteJobAction {
	/// Exclusively creates and bootstraps the requested signed owner.
	Create {
		/// Owner identity unique to the new job.
		token: OwnerToken,
		/// Independently observed UTC time of admission.
		created: OwnerTimestamp,
	},
	/// Authenticates and replays the selected existing job under a new lease.
	Resume,
}

pub(crate) enum AttemptAdmission<'held> {
	Initial(Option<RecoveryReadLease<'held>>),
	Retry(ReadyRetry<'held>),
}

impl AttemptAdmission<'_> {
	fn check_before_dial(&self) -> Result<(), Error> {
		match self {
			Self::Initial(_) => Ok(()),
			Self::Retry(ready) => ready.lease.recheck(),
		}
	}
}

/// Independently selected trust for one provisioned destination attestation.
pub struct RemoteDestinationAttestation<'trust> {
	/// Exact bounded signed artifact.
	pub record: &'trust [u8],
	/// Expected attestor independent of the selected job owner.
	pub attestor: [u8; 16],
	/// Trusted verification key for the attestor.
	pub key: &'trust ed25519_dalek::VerifyingKey,
	/// Exact independently configured campaign, build and route class.
	pub scope: RemoteQualificationScope,
}

/// Explicit native destination, owner profile, exact remote scope and active authority.
pub struct RemoteDownloadRequest<'request> {
	/// Original held native destination.
	pub root: &'request DestinationRoot,
	/// Protected ordinary job owner key path.
	pub profile: &'request Path,
	/// Signed job identity used to select its fixed private name.
	pub job: JournalJobId,
	/// Explicitly selected initial or retained job action.
	pub action: RemoteJobAction,
	/// Exact scope approved through the current grant and authenticated source route.
	pub scope: &'request RemoteDownloadScope,
	/// Explicit selected-stream loss policy.
	pub metadata: ApprovedSftpMetadata,
	/// Active serialized foreground authority for the scope.
	pub grant: &'request RemoteGrant,
	/// Independently provisioned and trusted qualification.
	pub qualification: RemoteDestinationAttestation<'request>,
}

/// Failures preserve their actual private journal and namespace state.
#[derive(Debug)]
pub enum RemoteDownloadFailure {
	/// Native job admission, replay or adapter failure.
	Job(Error),
	/// The retained job could not be admitted under the current exclusive lease.
	ResumeAdmission(Error),
	/// Provisioned signed destination qualification was refused.
	Attestation(RemoteQualificationError),
	/// SSH source selection, connection or terminal evidence was refused.
	Source(SftpSourceError),
	/// Capture stopped before publication, possibly leaving a private observed uncertainty record.
	Capture {
		/// Exact capture boundary and cause.
		cause: Box<CaptureError<SftpSourceError, NativeCaptureStageError, Error>>,
		/// Failed attempt to record a required uncertainty marker, if any.
		record_failure: Option<Error>,
		/// Independent failure to observe the original route's physical retirement.
		route_failure: Option<RemoteRouteCloseError>,
		/// Retained native observations or a separate failure to obtain them.
		retry: Option<Result<Box<RemoteRetryStamp>, Error>>,
	},
	/// Capture completed but transport retirement was not confirmed.
	SourceRetirement {
		/// Exact transport retirement boundary.
		cause: RemoteRouteCloseError,
		/// Failed attempt to record a required uncertainty marker, if any.
		record_failure: Option<Error>,
	},
	/// Engine finalization returned an exact last confirmed head and reason.
	Finalization(Box<FinalizationFailure<Error, Error, StageFinalizationError, Error>>),
	/// The engine obtained and committed an outcome, but independent artifact association failed.
	CommittedReceiptReadback {
		/// Confirmed completion evidence to retain for reconciliation.
		result: Box<CommittedRemoteReceipt>,
		/// What prevented independent readback.
		cause: Error,
	},
}

impl fmt::Display for RemoteDownloadFailure {
	fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Job(error) => error.fmt(out),
			Self::ResumeAdmission(error) => write!(out, "retained job admission failed ({error})"),
			Self::Attestation(error) => error.fmt(out),
			Self::Source(error) => error.fmt(out),
			Self::Capture {
				cause,
				record_failure,
				route_failure,
				retry,
			} => {
				cause.fmt(out)?;
				if let Some(error) = route_failure {
					write!(
						out,
						". The original route's retirement was unconfirmed ({error})"
					)?;
				}
				if let Some(Err(error)) = retry {
					write!(
						out,
						". The retained retry observations were refused ({error})"
					)?;
				}
				write_record_failure(out, record_failure.as_ref())
			}
			Self::SourceRetirement {
				cause,
				record_failure,
			} => {
				cause.fmt(out)?;
				write_record_failure(out, record_failure.as_ref())
			}
			Self::Finalization(error) => error.fmt(out),
			Self::CommittedReceiptReadback { cause, .. } => {
				write!(
					out,
					"publication and receipt need read-only reconciliation ({cause})"
				)
			}
		}
	}
}

fn write_record_failure(out: &mut fmt::Formatter<'_>, error: Option<&Error>) -> fmt::Result {
	if let Some(error) = error {
		write!(out, ". The private failure record also failed ({error})")?;
	}
	Ok(())
}

impl std::error::Error for RemoteDownloadFailure {}

impl From<Error> for RemoteDownloadFailure {
	fn from(cause: Error) -> Self {
		Self::Job(cause)
	}
}

impl From<SftpSourceError> for RemoteDownloadFailure {
	fn from(cause: SftpSourceError) -> Self {
		Self::Source(cause)
	}
}

fn qualify_destination(
	request: &RemoteDownloadRequest<'_>,
) -> Result<(LocalProfile, RemoteDestinationQualification), RemoteDownloadFailure> {
	let profile = LocalProfile::open(request.profile).map_err(Error::from)?;
	let qualification = &request.qualification;
	if measure_running_executable().map_err(Error::from)? != qualification.scope.build {
		return Err(RemoteDownloadFailure::Attestation(
			RemoteQualificationError::Scope,
		));
	}
	let owner_key = profile.verification_key();
	let trust = RemoteQualificationTrust {
		attestor: qualification.attestor,
		attestor_key: qualification.key,
		owner_key: &owner_key,
		scope: qualification.scope,
	};
	let facts = observe_remote_destination(request.root).map_err(Error::Qualification)?;
	let verified = verify_remote_destination_qualification(qualification.record, &trust, &facts)
		.map_err(RemoteDownloadFailure::Attestation)?;
	Ok((profile, verified))
}

fn capture_failure(
	cause: CaptureError<SftpSourceError, NativeCaptureStageError, Error>,
	route_failure: Option<RemoteRouteCloseError>,
	record: impl FnOnce(RemoteUncertainBoundary) -> Result<(), Error>,
) -> RemoteDownloadFailure {
	// V1 records no stage-write uncertainty. Preserve the actual cause for
	// the foreground result and record independent route uncertainty only.
	let boundary = capture_uncertainty(&cause, route_failure);
	let record_failure = boundary.and_then(|boundary| record(boundary).err());
	RemoteDownloadFailure::Capture {
		cause: Box::new(cause),
		record_failure,
		route_failure,
		retry: None,
	}
}

fn capture_uncertainty<R, W, C>(
	cause: &CaptureError<R, W, C>,
	route_failure: Option<RemoteRouteCloseError>,
) -> Option<RemoteUncertainBoundary> {
	match cause {
		CaptureError::SourceFinish(_) => Some(RemoteUncertainBoundary::TerminalSource),
		CaptureError::Stage {
			step: StageStep::SyncPrefix { .. } | StageStep::Close,
			..
		} => Some(RemoteUncertainBoundary::StageBarrier),
		_ if route_failure.is_some() => Some(RemoteUncertainBoundary::TerminalSource),
		_ => None,
	}
}

#[test]
fn unconfirmed_route_retirement_records_terminal_source_unless_the_stage_barrier_failed() {
	let read: CaptureError<(), (), ()> = CaptureError::Read {
		offset: 4096,
		cause: (),
	};
	let route_failure = Some(RemoteRouteCloseError::SocketTimeout);
	assert_eq!(capture_uncertainty(&read, None), None);
	assert_eq!(
		capture_uncertainty(&read, route_failure),
		Some(RemoteUncertainBoundary::TerminalSource)
	);
	assert_eq!(
		capture_uncertainty(&CaptureError::<(), (), ()>::SourceFinish(()), None),
		Some(RemoteUncertainBoundary::TerminalSource)
	);
	let barrier: CaptureError<(), (), ()> = CaptureError::Stage {
		step: StageStep::Close,
		cause: (),
	};
	assert_eq!(
		capture_uncertainty(&barrier, route_failure),
		Some(RemoteUncertainBoundary::StageBarrier)
	);
}

#[test]
fn write_failure_records_only_an_independent_unconfirmed_route() {
	use exacopy_endpoint::IoError;
	use exacopy_platform::linux::StageError;
	use std::cell::Cell;

	let preflight = || StageError::Admission(std::io::Error::other("deadline"));
	let after_count = || {
		StageError::WriteOutcomeUnknown(IoError::System {
			offset: 4098,
			source: std::io::Error::other("deadline after short write"),
		})
	};
	for cause in [preflight(), StageError::IdentityChanged, after_count()] {
		let result = capture_failure(
			CaptureError::Stage {
				step: StageStep::Write { offset: 4096 },
				cause: cause.into(),
			},
			None,
			|boundary| panic!("write failure emitted {boundary:?}"),
		);
		assert!(matches!(
			result,
			RemoteDownloadFailure::Capture {
				retry: None,
				record_failure: None,
				route_failure: None,
				..
			}
		));
	}
	let records = Cell::new(0);
	let _ = capture_failure(
		CaptureError::Stage {
			step: StageStep::Write { offset: 4096 },
			cause: after_count().into(),
		},
		Some(RemoteRouteCloseError::WorkerTimeout),
		|boundary| {
			assert_eq!(boundary, RemoteUncertainBoundary::TerminalSource);
			records.set(records.get() + 1);
			Ok(())
		},
	);
	assert_eq!(records.get(), 1);
}
