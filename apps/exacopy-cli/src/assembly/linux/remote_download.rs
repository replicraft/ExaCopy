//! Application-only execution of one explicitly admitted agentless SFTP attempt.

use std::fmt;
use std::num::NonZeroU64;
use std::path::Path;

use exacopy_endpoint::remote_source::{SftpPath, SftpPathRoot, SourceEpoch};
use exacopy_journal::remote_download::qualification::{
	RemoteQualificationError, RemoteQualificationScope, RemoteQualificationTrust,
	verify_remote_destination_qualification,
};
use exacopy_journal::remote_download::{
	RemoteDownloadScope, RemoteSourceObservation, RemoteUncertainBoundary,
};
use exacopy_journal::{JournalJobId, OwnerTimestamp, OwnerToken, StreamLength};
use exacopy_platform::linux::{
	DestinationRoot, RecoveryReadLease, RemoteDestinationEligibility, observe_remote_destination,
};
use exacopy_sftp::{
	PendingSftpPathRequest, PendingSourceOwner, SftpSourceError, open_pending_path_source,
};
use exacopy_transfer::remote_capture::{CaptureError, StageStep, capture_live};
use exacopy_transfer::remote_finalization::{
	CommittedRemoteReceipt, FinalizationFailure, RemoteFinalizationOutcome,
	RemoteFinalizationRequest, finalize_capture,
};
use exacopy_transfer::remote_metadata::ApprovedSftpMetadata;
use uuid::Uuid;

use crate::profile::{LocalProfile, kernel_random};

pub(crate) use super::remote_journal::Error as RemoteJobError;
use super::remote_journal::{
	Error, IntentReadback, RemoteActivation, RemoteJobLease, bootstrap, component,
};
use super::remote_stage::{
	FinalizingCaptureStage, NativeCaptureStage, NativeCaptureStageError, PrefixBarrier,
	PublicationContext, StageFinalizationError,
};

mod authority;
mod build;
mod source;
use authority::EffectAuthority;
pub use authority::RemoteGrant;
pub(super) use authority::native_authority;
pub use build::measure_running_executable;

pub(crate) use source::DirectConnectError;
#[cfg(feature = "experimental-ssh-wireguard")]
pub(crate) use source::EmbeddedConnectError;
pub use source::{
	ConnectedRemoteSource, ConnectingRemoteSource, CurrentEmbeddedStream,
	EmbeddedStreamObservation, RemoteRoutePeer,
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
				record_failure: Some(error),
			} => {
				write!(
					out,
					"{cause}. The private failure record also failed ({error})"
				)
			}
			Self::Capture {
				cause,
				record_failure: None,
			} => cause.fmt(out),
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

/// Executes one fresh-source attempt and its native finalization under the checked job lease.
/// The supplied session belongs to the route owner and retires before public effects.
/// # Errors
/// Refuses unauthorized, stale or unsupported state and preserves all prior artifacts.
pub(crate) async fn download_remote(
	request: RemoteDownloadRequest<'_>,
	connection: ConnectedRemoteSource<'_>,
	startup_read: Option<RecoveryReadLease<'_>>,
) -> Result<RemoteFinalizationOutcome, RemoteDownloadFailure> {
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
	let native = RemoteDestinationEligibility::admit(request.root, Some(&verified))
		.map_err(Error::Qualification)?;
	let qualified = (qualification.scope.route, native);
	let activation = RemoteActivation::admit(
		request.root,
		request.scope,
		request.metadata,
		request.grant,
		&qualified,
	)?;
	let authority = activation.publication_authority();
	let (mut session, mut owner) = connection.into_current(authority.scope, request.grant)?;
	let attempt = owner.attempt();
	let existing = match (request.action, startup_read) {
		(RemoteJobAction::Resume, Some(lease)) => {
			// The cooperative lock has covered replay, authentication and qualification.
			// Reopening under the exclusive lock rechecks the full held history.
			drop(lease);
			Some(
				RemoteJobLease::open_existing(&profile, request.job, activation)
					.map_err(RemoteDownloadFailure::ResumeAdmission)?,
			)
		}
		(RemoteJobAction::Create { .. }, None) => None,
		_ => return Err(Error::Binding.into()),
	};
	let epoch = SourceEpoch::new(match &existing {
		Some(held) => held.next_source_epoch()?,
		None => NonZeroU64::MIN,
	});
	let raw = request.scope.source.path();
	let rooted = request.scope.source.path_root();
	let names = raw
		.strip_prefix(b"/")
		.unwrap_or(raw)
		.split(|byte| *byte == b'/')
		.map(component)
		.collect::<Result<Vec<_>, _>>()?;
	let path = match rooted {
		SftpPathRoot::AccountRelative => SftpPath::AccountRelative(&names),
		SftpPathRoot::Absolute => SftpPath::Absolute(&names),
	};
	let pending = open_pending_path_source(
		&mut session,
		PendingSftpPathRequest {
			path,
			attempt,
			epoch,
		},
		&mut owner,
	)
	.await?;
	activation.recheck()?;
	owner
		.check_connecting(attempt)
		.map_err(SftpSourceError::Binding)?;
	let observed = pending.observation();
	let length = StreamLength::new(observed.length).map_err(|_| Error::Attempt)?;
	if length.get() > request.scope.maximum_extent.get() {
		return Err(Error::Attempt.into());
	}
	let observation = RemoteSourceObservation::new(length, observed.mode, observed.modified)
		.map_err(Error::from)?;
	let source_binding = owner
		.admit_pending(&pending)
		.map_err(SftpSourceError::Binding)?;
	let mut source = pending.activate(source_binding, |binding| owner.check_binding(binding))?;
	let lease = match (existing, request.action) {
		(Some(held), RemoteJobAction::Resume) => held,
		(None, RemoteJobAction::Create { token, created }) => {
			let held = bootstrap(&profile, request.job, created, token, activation)?;
			RemoteJobLease::open_bootstrap(&profile, request.job, activation, held)?
		}
		_ => return Err(Error::Binding.into()),
	};
	let intent = IntentReadback::default();
	let publication = PublicationContext {
		job: lease.context(),
		authority,
		grant: request.grant,
		eligibility: &qualified.1,
		intent: &intent,
	};
	let mut nonce = [0; 16];
	kernel_random(&mut nonce).map_err(Error::from)?;
	let name = format!("capture-{}", Uuid::from_bytes(nonce));
	let candidate = lease.candidate(component(name.as_bytes())?)?;
	let mut ledger = lease.open_fresh_capture(&candidate)?;
	let mut allocation = ledger.allocate(
		&candidate,
		NonZeroU64::new(epoch.get()).ok_or(Error::Binding)?,
		observation,
		nonce,
	)?;
	let bound = allocation.create(&mut ledger)?;
	let barrier = PrefixBarrier::new(bound.prefix_scope);
	let native = NativeCaptureStage::new(
		bound.writer,
		lease.job(),
		bound.name,
		bound.target,
		bound.directory,
		bound.length,
		&barrier,
	)
	.map_err(Error::from)?;
	let stage = FinalizingCaptureStage(native, publication);
	let mut scratch = vec![0; 64 * 1024];
	let captured = capture_live(
		&mut source,
		epoch,
		stage,
		&mut ledger.checkpoints(&barrier),
		&mut scratch,
	)
	.await;
	drop(source);
	let late = owner.retire(source_binding, session).await;
	let captured = match (captured, late) {
		(Ok(value), Ok(())) => value,
		(Ok(_), Err(cause)) => {
			return Err(capture_failure(
				&mut ledger,
				CaptureError::SourceFinish(SftpSourceError::Binding(cause)),
			));
		}
		(Err(cause), _) => return Err(capture_failure(&mut ledger, cause)),
	};
	let history = lease.finalization_history(&ledger)?;
	let mut journal = ledger.finalization(&intent)?;
	let result = finalize_capture(
		RemoteFinalizationRequest {
			owner: history.owner,
			replay: &history.replay,
			allocation: &history.allocation,
			prepared: &history.prepared,
			policy: request.metadata,
			authority,
		},
		captured,
		&mut journal,
		&mut EffectAuthority(activation),
		&lease.receipts(),
	)
	.map_err(|cause| RemoteDownloadFailure::Finalization(Box::new(cause)))?;
	if let RemoteFinalizationOutcome::PublishedWithOmissions(receipt) = &result
		&& let Err(cause) = lease.check_committed_receipt(&ledger, receipt)
		&& let RemoteFinalizationOutcome::PublishedWithOmissions(result) = result
	{
		return Err(RemoteDownloadFailure::CommittedReceiptReadback {
			result: Box::new(result),
			cause,
		});
	}
	Ok(result)
}

fn capture_failure(
	ledger: &mut super::remote_journal::RemoteJobJournal<'_>,
	cause: CaptureError<SftpSourceError, NativeCaptureStageError, Error>,
) -> RemoteDownloadFailure {
	let boundary = match &cause {
		CaptureError::SourceFinish(_) => Some(RemoteUncertainBoundary::TerminalSource),
		CaptureError::Stage {
			step: StageStep::SyncPrefix { .. } | StageStep::Close,
			..
		} => Some(RemoteUncertainBoundary::StageBarrier),
		_ => None,
	};
	let record_failure = boundary.and_then(|boundary| ledger.record_failure(boundary).err());
	RemoteDownloadFailure::Capture {
		cause: Box::new(cause),
		record_failure,
	}
}
