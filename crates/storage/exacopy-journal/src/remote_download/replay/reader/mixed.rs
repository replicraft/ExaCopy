use crate::remote_download::RemoteUncertainBoundary;
use crate::remote_download::finalization_replay::RemoteFinalizationPhase as Legacy;

use super::{
	ContinuationReplayProfile, ContinuedHistory, FinalizationHistory, Frame, FrameKind, Read,
	RemoteBootstrapTrust, RemoteDownloadError, RemoteDownloadReplay, RemoteReplayBoundary,
	RemoteReplayIssue, RemoteReplayMismatch, ReplayValidation, ScanProfile, WitnessCloseoutHistory,
	accept_extended, scan,
};

pub(in crate::remote_download::replay) fn scan_witness_closeout(
	input: impl Read,
	trust: &RemoteBootstrapTrust<'_>,
	legacy: &mut FinalizationHistory,
	continued: &mut ContinuedHistory,
	mixed: &mut WitnessCloseoutHistory<'_>,
	max_bytes: u64,
	max_attempts: usize,
) -> Result<RemoteDownloadReplay, RemoteDownloadError> {
	scan(
		input,
		trust.owner(),
		ScanProfile {
			bootstrap: Some(trust),
			finalization: Some(legacy),
			continued: Some(continued),
			mixed: Some(mixed),
			retain_checkpoints: true,
			continuation_profile: ContinuationReplayProfile::Witness,
		},
		max_bytes,
		max_attempts,
	)
}

pub(super) fn profile_cap(
	mixed: &WitnessCloseoutHistory<'_>,
	replay: &RemoteDownloadReplay,
	legacy: Option<Legacy>,
	kind: FrameKind,
	max_attempts: usize,
) -> Result<Option<usize>, RemoteReplayIssue> {
	use FrameKind as K;
	if mixed.pass_count(replay.attempts().len()) >= max_attempts
		&& (matches!(kind, K::RemoteCaptureContinued | K::RemoteStageAllocated)
			|| (kind == K::RemoteCaptureRetired && !mixed.is_initial_legacy()))
	{
		return Err(RemoteReplayIssue::AttemptLimit);
	}
	if mixed.in_fresh_legacy() || mixed.is_initial_legacy() {
		if !legacy_admits(replay, legacy, kind, mixed.in_fresh_legacy()) {
			let problem =
				if replay.recorded_uncertainty().is_some() || legacy == Some(Legacy::Uncertain) {
					RemoteReplayMismatch::AfterUncertainty
				} else {
					RemoteReplayMismatch::Order
				};
			return Err(refusal(replay, kind, problem));
		}
		return Ok(None);
	}

	mixed.payload_cap(kind).map(Some).ok_or_else(|| {
		refusal(
			replay,
			kind,
			if mixed.uncertain() {
				RemoteReplayMismatch::AfterUncertainty
			} else {
				RemoteReplayMismatch::UnsupportedKind
			},
		)
	})
}

fn legacy_admits(
	replay: &RemoteDownloadReplay,
	phase: Option<Legacy>,
	kind: FrameKind,
	fresh: bool,
) -> bool {
	use FrameKind as K;
	if replay.recorded_uncertainty().is_some() {
		return false;
	}
	if replay.job_prepared().is_none() {
		return kind == K::JobPrepared;
	}
	if replay.stage_directory_prepared().is_none() {
		return kind == K::StageDirectoryPrepared;
	}
	match phase {
		Some(Legacy::Capture) => match replay.attempts().last() {
			None => kind == K::RemoteStageAllocated,
			Some(attempt) if attempt.prepared().is_none() => {
				matches!(kind, K::EntryPrepared | K::FailureRecorded)
					|| (!fresh && kind == K::RemoteStageAllocated)
			}
			Some(attempt) => {
				matches!(
					kind,
					K::RemoteStageAllocated
						| K::RangeCheckpoint
						| K::FailureRecorded
						| K::StageSealed
				) || (kind == K::RemoteCaptureContinued && attempt.checkpoint_count() != 0)
			}
		},
		Some(Legacy::Sealed) => matches!(kind, K::VerificationRecorded | K::RemoteCaptureRetired),
		Some(Legacy::Verified) => matches!(kind, K::MetadataRecorded | K::RemoteCaptureRetired),
		Some(Legacy::MetadataReady) => matches!(kind, K::PublishIntent | K::RemoteCaptureRetired),
		Some(Legacy::Retired) => kind == K::RemoteStageAllocated,
		Some(Legacy::Intent) => kind == K::PublishObserved,
		Some(Legacy::Published) => kind == K::DurabilityRecorded,
		Some(Legacy::Durable) => kind == K::ReceiptCommitted,
		_ => false,
	}
}

pub(super) struct Acceptance<'scope, 'owner, 'qualification> {
	pub(super) mixed: &'scope mut WitnessCloseoutHistory<'qualification>,
	pub(super) continued: &'scope mut ContinuedHistory,
	pub(super) legacy: &'scope mut FinalizationHistory,
	pub(super) trust: &'scope RemoteBootstrapTrust<'owner>,
	pub(super) validation: &'scope ReplayValidation<'owner>,
}

pub(super) fn accept(
	context: Acceptance<'_, '_, '_>,
	replay: &mut RemoteDownloadReplay,
	frame: Frame,
	end: RemoteReplayBoundary,
) -> Result<(), RemoteReplayIssue> {
	use FrameKind as K;
	let Acceptance {
		mixed,
		continued,
		legacy,
		trust,
		validation,
	} = context;
	let kind = frame.kind();
	let previous = replay.boundary();
	let mismatch = |problem| RemoteReplayIssue::Record {
		offset: previous.offset,
		kind,
		problem,
	};
	if mixed.retired() {
		let active = continued
			.active()
			.ok_or_else(|| mismatch(RemoteReplayMismatch::Order))?;
		replay.logical_previous = Some(active.epochs());
		let accepted = accept_extended(validation, replay, legacy, trust.owner(), frame);
		replay.logical_previous = None;
		accepted?;
		replay.active_checkpoints = Some(Vec::new());
		let qualification = mixed.fresh_qualification();
		legacy.select_fresh_archive(qualification);
		continued.select_fresh(qualification);
		mixed.note_fresh();
		return Ok(());
	}
	match (kind, continued.active()) {
		(K::RemoteCaptureContinued, Some(_)) => {
			continued
				.repeat(replay, trust, frame, end)
				.map_err(mismatch)?;
		}
		(K::RemoteCaptureContinued, None) | (K::RangeCheckpoint, Some(_)) => {
			continued
				.accept(replay, legacy.phase(), trust, frame, end)
				.map_err(mismatch)?;
		}
		(K::FailureRecorded, Some(active)) => {
			let failure = active
				.accept_failure(trust, previous, &frame)
				.map_err(mismatch)?;
			if !mixed.before_witness() && failure.boundary != RemoteUncertainBoundary::StageBarrier
			{
				return Err(mismatch(RemoteReplayMismatch::FailureBinding));
			}
			mixed.note_failure(failure);
			return Ok(());
		}
		(_, Some(active)) => {
			return mixed
				.accept(trust, replay, active, frame, end)
				.map_err(mismatch);
		}
		(_, None) => return accept_extended(validation, replay, legacy, trust.owner(), frame),
	}
	let active = continued
		.active()
		.ok_or_else(|| mismatch(RemoteReplayMismatch::Order))?;
	mixed.note_progress(active, kind);
	Ok(())
}

fn refusal(
	replay: &RemoteDownloadReplay,
	kind: FrameKind,
	problem: RemoteReplayMismatch,
) -> RemoteReplayIssue {
	RemoteReplayIssue::Record {
		offset: replay.boundary().offset,
		kind,
		problem,
	}
}
