use std::num::NonZeroU64;

use exacopy_endpoint::remote_source::{CapturedReadAt, SftpPath, SftpPathRoot, SourceEpoch};
use exacopy_journal::StreamLength;
use exacopy_journal::remote_download::{RemoteSourceObservation, RemoteUncertainBoundary};
use exacopy_platform::linux::{RecoveryReadLease, RemoteDestinationEligibility};
use exacopy_sftp::{
	PendingSftpPathRequest, PendingSourceOwner, SftpSourceError, open_pending_path_source,
};
use exacopy_ssh::ReadOnlySftp;
use exacopy_transfer::remote_capture::{CaptureError, capture_live};
use exacopy_transfer::remote_finalization::{
	RemoteFinalizationOutcome, RemoteFinalizationRequest, finalize_capture,
};
use uuid::Uuid;

use crate::profile::{LocalProfile, kernel_random};

use super::super::remote_journal::{
	Error, IntentReadback, RemoteActivation, RemoteJobLease, bootstrap, component,
};
use super::super::remote_stage::{
	FinalizingCaptureStage, NativeCaptureStage, PrefixBarrier, PublicationContext,
};
use super::source::SourceOwner;
use super::{
	ConnectedRemoteSource, EffectAuthority, ReadyRetry, RemoteDownloadFailure,
	RemoteDownloadRequest, RemoteJobAction, RemoteRetryLease, RemoteRetryStamp, capture_failure,
	qualify_destination,
};

/// Executes one fresh-source attempt and its native finalization under the checked job lease.
/// The supplied session belongs to the route owner and retires before public effects.
/// # Errors
/// Refuses unauthorized, stale or unsupported state and preserves all prior artifacts.
pub(crate) async fn download_remote(
	request: &RemoteDownloadRequest<'_>,
	connection: ConnectedRemoteSource<'_>,
	startup_read: Option<RecoveryReadLease<'_>>,
) -> Result<RemoteFinalizationOutcome, RemoteDownloadFailure> {
	let pre_effect = |cause: Error| match request.action {
		RemoteJobAction::Create { .. } => Error::BootstrapNotCreated(Box::new(cause)),
		RemoteJobAction::Resume => cause,
	};
	let (profile, verified) = qualify_destination(request).map_err(|cause| match cause {
		RemoteDownloadFailure::Job(cause) => RemoteDownloadFailure::Job(pre_effect(cause)),
		cause => cause,
	})?;
	let native = RemoteDestinationEligibility::admit(request.root, Some(&verified))
		.map_err(|cause| pre_effect(Error::Qualification(cause)))?;
	let qualified = (request.qualification.scope.route, native);
	let activation = RemoteActivation::admit(
		request.root,
		request.scope,
		request.metadata,
		request.grant,
		&qualified,
	)
	.map_err(pre_effect)?;
	let authority = activation.publication_authority();
	let (session, owner) = connection.into_current(authority.scope, request.grant)?;
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
		_ => return Err(pre_effect(Error::Binding).into()),
	};
	download_prepared(
		request,
		session,
		owner,
		CaptureAuthority {
			activation,
			eligibility: &qualified.1,
		},
		CaptureJob::Initial {
			profile: &profile,
			existing: existing.map(Box::new),
		},
	)
	.await
}

pub(crate) async fn download_retry(
	request: &RemoteDownloadRequest<'_>,
	connection: ConnectedRemoteSource<'_>,
	retry: ReadyRetry<'_>,
) -> Result<RemoteFinalizationOutcome, RemoteDownloadFailure> {
	let activation = retry.lease.activation();
	let authority = activation.publication_authority();
	let (session, owner) = connection.into_current(authority.scope, request.grant)?;
	download_prepared(
		request,
		session,
		owner,
		CaptureAuthority {
			activation,
			eligibility: retry.eligibility,
		},
		CaptureJob::Retry(retry.lease),
	)
	.await
}

struct CaptureAuthority<'a> {
	activation: RemoteActivation<'a>,
	eligibility: &'a RemoteDestinationEligibility<'a>,
}

enum CaptureJob<'a> {
	Initial {
		profile: &'a LocalProfile,
		existing: Option<Box<RemoteJobLease<'a>>>,
	},
	Retry(Box<RemoteRetryLease<'a>>),
}

async fn download_prepared(
	request: &RemoteDownloadRequest<'_>,
	mut session: ReadOnlySftp,
	mut owner: SourceOwner<'_>,
	context: CaptureAuthority<'_>,
	job: CaptureJob<'_>,
) -> Result<RemoteFinalizationOutcome, RemoteDownloadFailure> {
	let pre_effect = |cause| {
		if matches!(&job, CaptureJob::Initial { existing: None, .. }) {
			Error::BootstrapNotCreated(Box::new(cause))
		} else {
			cause
		}
	};
	let activation = context.activation;
	let authority = activation.publication_authority();
	let attempt = owner.attempt();
	let allocated_epoch = match &job {
		CaptureJob::Initial {
			existing: Some(held),
			..
		} => held.next_source_epoch()?,
		CaptureJob::Initial { existing: None, .. } => NonZeroU64::MIN,
		CaptureJob::Retry(held) => held.source_epoch(),
	};
	let epoch = SourceEpoch::new(allocated_epoch);
	let raw = request.scope.source.path();
	let rooted = request.scope.source.path_root();
	let names = raw
		.strip_prefix(b"/")
		.unwrap_or(raw)
		.split(|byte| *byte == b'/')
		.map(component)
		.collect::<Result<Vec<_>, _>>()
		.map_err(pre_effect)?;
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
	activation.recheck().map_err(pre_effect)?;
	owner
		.check_connecting(attempt)
		.map_err(SftpSourceError::Binding)?;
	let observed = pending.observation();
	let length = StreamLength::new(observed.length).map_err(|_| pre_effect(Error::Attempt))?;
	if length.get() > request.scope.maximum_extent.get() {
		return Err(pre_effect(Error::Attempt).into());
	}
	let observation = RemoteSourceObservation::new(length, observed.mode, observed.modified)
		.map_err(|cause| pre_effect(Error::from(cause)))?;
	let source_binding = owner
		.admit_pending(&pending)
		.map_err(SftpSourceError::Binding)?;
	let mut source = pending.activate(source_binding, |binding| owner.check_binding(binding))?;
	let (lease, preview, _retained_pins) = match job {
		CaptureJob::Retry(held) => {
			if observation != held.previous_source_observation() {
				return Err(RemoteDownloadFailure::Source(SftpSourceError::Observation));
			}
			source.recheck().await?;
			let (lease, preview, pins) = held
				.consume(observation, allocated_epoch)
				.map_err(RemoteDownloadFailure::ResumeAdmission)?;
			(lease, Some(preview), Some(pins))
		}
		CaptureJob::Initial {
			existing: Some(held),
			..
		} => (*held, None, None),
		CaptureJob::Initial {
			profile,
			existing: None,
		} => {
			let RemoteJobAction::Create { token, created } = request.action else {
				return Err(Error::Binding.into());
			};
			let held = bootstrap(profile, request.job, created, token, activation)?;
			(
				RemoteJobLease::open_bootstrap(profile, request.job, activation, held)?,
				None,
				None,
			)
		}
	};
	let intent = IntentReadback::default();
	let publication = PublicationContext {
		job: lease.context(),
		authority,
		activation,
		eligibility: context.eligibility,
		intent: &intent,
	};
	let mut nonce = [0; 16];
	let fresh_name;
	let name = match &preview {
		Some(seed) => seed.name(),
		None => {
			kernel_random(&mut nonce).map_err(Error::from)?;
			fresh_name = format!("capture-{}", Uuid::from_bytes(nonce));
			fresh_name.as_bytes()
		}
	};
	let stage_name = component(name)?;
	let candidate = lease.candidate(stage_name)?;
	let mut ledger = if preview.is_some() {
		// A retained retry only opens the accepted Capture head. It cannot
		// retire a finalized predecessor through the explicit-resume path.
		lease.open_writer(&candidate)?
	} else {
		lease.open_fresh_capture(&candidate)?
	};
	let mut allocation = match &preview {
		Some(seed) => ledger.allocate_retry(&candidate, seed, observation)?,
		None => ledger.allocate(&candidate, allocated_epoch, observation, nonce)?,
	};
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
	let grant = owner.retry_grant();
	let retirement = owner.retire(source_binding, session).await;
	let captured = match (captured, retirement.binding, retirement.route) {
		(Ok(value), Ok(()), Ok(())) => value,
		(Ok(_), Err(cause), route) => {
			return Err(capture_failure(
				CaptureError::SourceFinish(SftpSourceError::Binding(cause)),
				route.err(),
				|boundary| ledger.record_failure(boundary),
			));
		}
		(Ok(_), Ok(()), Err(cause)) => {
			return Err(RemoteDownloadFailure::SourceRetirement {
				cause,
				record_failure: ledger
					.record_failure(RemoteUncertainBoundary::TerminalSource)
					.err(),
			});
		}
		(
			Err(
				cause @ CaptureError::Read {
					offset,
					cause: SftpSourceError::ReadTimeout,
				},
			),
			Ok(()),
			Ok(()),
		) => {
			// The failed capture has already dropped its writer. Release the
			// stage factory's distinct access guard before retaining read pins.
			drop(allocation);
			let retry = ledger
				.stamp_failed_read(stage_name, allocated_epoch, offset)
				.map(|native| Box::new(RemoteRetryStamp::new(native, grant, source_binding)));
			return Err(RemoteDownloadFailure::Capture {
				cause: Box::new(cause),
				record_failure: None,
				route_failure: None,
				retry: Some(retry),
			});
		}
		(Err(cause), _, route) => {
			return Err(capture_failure(cause, route.err(), |boundary| {
				ledger.record_failure(boundary)
			}));
		}
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
