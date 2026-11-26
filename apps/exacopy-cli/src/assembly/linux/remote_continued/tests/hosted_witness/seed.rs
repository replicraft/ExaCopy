//! Genuine ordinary capture stopped at the clean, fully covered kind-3 boundary.

use std::io::{Error, ErrorKind};
use std::num::NonZeroU64;
use std::sync::Arc;

use exacopy_content::measure_at;
use exacopy_endpoint::remote_source::{SftpPath, SftpPathRoot, SourceEpoch};
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
use exacopy_journal::remote_download::finalization_replay::RemoteFinalizationPhase;
use exacopy_journal::remote_download::qualification::{
	RemoteQualificationRouteClass, RemoteQualificationTrust,
	verify_remote_destination_qualification,
};
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::{
	MAX_REMOTE_CHECKPOINT_BYTES, RemoteDownloadBody, RemoteDownloadRecord, RemoteDownloadRoute,
	RemoteSourceObservation,
};
use exacopy_journal::{StreamDigest, StreamLength};
use exacopy_platform::linux::{
	RemoteDestinationEligibility, StageError, TargetStatus, observe_remote_destination,
};
use exacopy_sftp::{PendingSftpPathRequest, open_pending_path_source};
use exacopy_transfer::remote_capture::capture_live;
use uuid::Uuid;

use crate::assembly::linux::remote_download::{
	AttemptAdmission, RemoteDownloadRequest, RemoteGrant, RemoteJobAction, SourceInvocation,
	measure_running_executable,
};
use crate::assembly::linux::remote_journal::{
	Error as RemoteJobError, IntentReadback, RemoteActivation, RemoteJobLease, bootstrap,
	component, record_identity,
};
use crate::assembly::linux::remote_stage::{
	FinalizingCaptureStage, NativeCaptureStage, PrefixBarrier, PublicationContext,
};
use crate::profile::{LocalProfile, kernel_random};
use crate::remote_frontdoor::{ApprovedRoute, SshProfile};

mod driver;

pub(super) struct ExpectedSeed {
	pub(super) source: RemoteSourceObservation,
	pub(super) digest: [u8; 32],
}

pub(super) struct SeedEvidence {
	pub(super) stage: String,
	pub(super) boundary: RemoteReplayBoundary,
	pub(super) original_qualification: [u8; 32],
	pub(super) source_digest: [u8; 32],
}

pub(super) async fn capture_direct_seed(
	request: &RemoteDownloadRequest<'_>,
	ssh: &SshProfile,
	grant: &Arc<RemoteGrant>,
	expected: ExpectedSeed,
) -> Result<SeedEvidence, Error> {
	let RemoteJobAction::Create { token, created } = request.action else {
		return Err(refused());
	};
	let (RemoteDownloadRoute::ResolvedDirect { endpoint }, ApprovedRoute::Direct(selected)) =
		(request.scope.source.route(), &ssh.route)
	else {
		return Err(refused());
	};
	let extent = expected.source.length().get();
	let attestation = &request.qualification;
	let profile = LocalProfile::open(request.profile)
		.map_err(RemoteJobError::from)
		.map_err(Error::other)?;
	let owner_key = profile.verification_key();
	if endpoint != *selected
		|| !std::ptr::eq(grant.as_ref(), request.grant)
		|| !(1..=MAX_REMOTE_CHECKPOINT_BYTES).contains(&extent)
		|| extent > request.scope.maximum_extent.get()
		|| expected.digest == [0; 32]
		|| attestation.scope.route != RemoteQualificationRouteClass::DirectPinnedTcpV1
		|| measure_running_executable().map_err(Error::other)? != attestation.scope.build
		|| request.scope.destination.root()
			!= profile
				.root_id(request.root.identity())
				.map_err(RemoteJobError::from)
				.map_err(Error::other)?
		|| request
			.root
			.target_status(component(request.scope.destination.target()).map_err(Error::other)?)
			.map_err(Error::other)?
			!= TargetStatus::Absent
	{
		return Err(refused());
	}

	let facts = observe_remote_destination(request.root).map_err(Error::other)?;
	let selected = verify_remote_destination_qualification(
		attestation.record,
		&RemoteQualificationTrust {
			attestor: attestation.attestor,
			attestor_key: attestation.key,
			owner_key: &owner_key,
			scope: attestation.scope,
		},
		&facts,
	)
	.map_err(Error::other)?;
	let qualified = (
		attestation.scope.route,
		RemoteDestinationEligibility::admit(request.root, Some(&selected)).map_err(Error::other)?,
	);
	let activation = RemoteActivation::admit(
		request.root,
		request.scope,
		request.metadata,
		request.grant,
		&qualified,
	)
	.map_err(Error::other)?;
	let authority = activation.publication_authority();

	let invocation = SourceInvocation::new(request.scope, grant).map_err(Error::other)?;
	let connected = invocation
		.claim()
		.map_err(Error::other)?
		.connect_direct(ssh, &AttemptAdmission::Initial(None))
		.await
		.map_err(Error::other)?;
	let (mut session, mut owner) = connected
		.into_current(authority.scope, grant)
		.map_err(Error::other)?;

	let raw = request.scope.source.path();
	let names = raw
		.strip_prefix(b"/")
		.unwrap_or(raw)
		.split(|byte| *byte == b'/')
		.map(component)
		.collect::<Result<Vec<_>, _>>()
		.map_err(Error::other)?;
	let path = match request.scope.source.path_root() {
		SftpPathRoot::AccountRelative => SftpPath::AccountRelative(&names),
		SftpPathRoot::Absolute => SftpPath::Absolute(&names),
	};
	let epoch = SourceEpoch::new(NonZeroU64::MIN);
	let pending = open_pending_path_source(
		&mut session,
		PendingSftpPathRequest {
			path,
			attempt: owner.attempt(),
			epoch,
		},
		&mut owner,
	)
	.await
	.map_err(Error::other)?;
	let observed = pending.observation();
	let observation = RemoteSourceObservation::new(
		StreamLength::new(observed.length).map_err(Error::other)?,
		observed.mode,
		observed.modified,
	)
	.map_err(Error::other)?;
	let binding = owner.admit_pending(&pending).map_err(Error::other)?;
	let mut retirement = Some(owner.prepare_retirement(binding).map_err(Error::other)?);
	let result = async {
		if observation != expected.source {
			return Err(refused());
		}
		let mut source = pending
			.activate(binding, |binding| owner.check_binding(binding))
			.map_err(Error::other)?;
		let held =
			bootstrap(&profile, request.job, created, token, activation).map_err(Error::other)?;
		let lease = RemoteJobLease::open_bootstrap(&profile, request.job, activation, held)
			.map_err(Error::other)?;
		let mut nonce = [0; 16];
		kernel_random(&mut nonce).map_err(RemoteJobError::from).map_err(Error::other)?;
		let stage_name = format!("capture-{}", Uuid::from_bytes(nonce));
		let name = component(stage_name.as_bytes()).map_err(Error::other)?;
		let candidate = lease.candidate(name).map_err(Error::other)?;
		let mut ledger = lease.open_fresh_capture(&candidate).map_err(Error::other)?;
		let mut allocation = ledger
			.allocate(&candidate, NonZeroU64::MIN, observation, nonce)
			.map_err(Error::other)?;
		let bound = allocation.create(&mut ledger).map_err(Error::other)?;
		let stage_id = bound.prefix_scope.stage;
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
		.map_err(Error::other)?;
		let intent = IntentReadback::default();
		let stage = FinalizingCaptureStage(
			native,
			PublicationContext {
				job: lease.context(),
				authority,
				activation,
				eligibility: &qualified.1,
				intent: &intent,
			},
		);
		let mut scratch = vec![0; 64 * 1024];
		let captured = capture_live(
			&mut source,
			epoch,
			stage,
			&mut ledger.checkpoints(&barrier),
			&mut scratch,
		)
		.await
		.map_err(Error::other)?;
		let (closed, stream) = captured.into_parts();
		if stream.length != extent
			|| stream.source_digest != expected.digest
			|| stream.stage_digest.as_bytes() != &expected.digest
		{
			return Err(refused());
		}
		drop(source);
		owner.check_binding(binding).map_err(Error::other)?;
		// Require transport drain before attesting the retained boundary under the lock.
		let drained = retirement.take().ok_or_else(refused)?.finish(epoch).await
			.map_err(Error::other)?;
		if drained.binding() != binding || !drained.matches_invocation(grant) {
			return Err(refused());
		}
		let history = lease.finalization_history(&ledger).map_err(Error::other)?;
		let boundary = history.replay.boundary();
		let [attempt] = history.replay.attempts() else {
			return Err(refused());
		};
		let prepared = attempt.prepared().ok_or_else(refused)?;
		let target = component(request.scope.destination.target()).map_err(Error::other)?;
		let inventory = lease.job().inventory(name, target).map_err(Error::other)?;
		let observed_stage = inventory.stage().ok_or_else(refused)?;
		if history.replay.issue().is_some()
			|| history.replay.phase() != RemoteFinalizationPhase::Capture
			|| history.replay.expected_qualification() != activation.qualification_digest
			|| attempt.checkpoint_count() != 1
			|| attempt.covered_extent() != extent
			|| prepared.file != record_identity(stage_id)
			|| observed_stage.identity() != stage_id
			|| observed_stage.observation().link_count() != 1
			|| observed_stage.len() != extent
			|| inventory.target().is_some()
			|| !matches!(lease.job().open_receipt(), Err(StageError::System(error))
				if error.kind() == ErrorKind::NotFound)
		{
			return Err(refused());
		}

		observed_stage.recheck_observation().map_err(Error::other)?;
		let reopened_digest = measure_at(extent, &mut scratch, |offset, bytes| {
			observed_stage.read_exact_at(offset, bytes)
		})
		.map_err(Error::other)?;
		observed_stage.check_logical_eof().map_err(Error::other)?;
		observed_stage.recheck_observation().map_err(Error::other)?;
		if reopened_digest.as_bytes() != &expected.digest {
			return Err(refused());
		}

		let mut segment = lease.job().open_first_segment().map_err(Error::other)?;
		if segment.len() != boundary.offset {
			return Err(refused());
		}
		let mut reader = FrameReader::new(&mut segment, ChainHead::start());
		let mut last = None;
		while let Some(frame) = reader.next_frame().map_err(Error::other)? {
			last = Some(frame);
		}
		let last = last.ok_or_else(refused)?;
		let record = RemoteDownloadRecord::from_frame(&last).map_err(Error::other)?;
		if last.kind() != FrameKind::RangeCheckpoint
			|| !matches!(record.body(), RemoteDownloadBody::RangeCheckpoint {
				prepared: head, ordinal: 1, offset: 0, length, digest, ..
			} if head == prepared.head && length == extent && digest == StreamDigest::from_bytes(expected.digest))
			|| reader.head() != boundary.head
			|| reader.offset() != boundary.offset
		{
			return Err(refused());
		}
		segment.check_logical_eof().map_err(Error::other)?;
		segment.recheck_observation().map_err(Error::other)?;
		inventory.recheck().map_err(Error::other)?;
		drop(closed);
		Ok(SeedEvidence {
			stage: stage_name.clone(),
			boundary,
			original_qualification: activation.qualification_digest,
			source_digest: expected.digest,
		})
	}
	.await;
	drop(session);
	if let Some(retirement) = retirement {
		let _drained = retirement.finish(epoch).await.map_err(Error::other)?;
	}
	result
}

fn refused() -> Error {
	Error::new(
		ErrorKind::InvalidData,
		"witness seed selection or capture boundary differs",
	)
}
