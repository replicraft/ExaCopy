use std::cell::Cell;
use std::io::Read;

use crate::frame::{
	ChainHead, FRAME_OVERHEAD_BYTES, Frame, FrameKind, FrameProblem, FrameReadError, FrameReader,
	MAX_PAYLOAD_BYTES,
};

use super::super::continuation::{MAX_REMOTE_CONTINUATION_PAYLOAD_BYTES, replay::ContinuedHistory};
use super::super::finalization::MAX_REMOTE_FINALIZATION_BYTES;
use super::super::finalization_replay::{FinalizationHistory, RemoteFinalizationPhase};
use super::super::retirement::MAX_REMOTE_RETIREMENT_BYTES;
use super::super::{
	MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES, MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES, RemoteBootstrapTrust,
	RemoteDownloadContext, RemoteDownloadError, RemoteDownloadOwner, RemoteDownloadOwnerRecord,
	RemoteDownloadRecord, RemoteScopeDigest,
};
use super::{
	ContinuationReplayProfile, RemoteDownloadReplay, RemoteReplayBoundary, RemoteReplayIssue,
	RemoteReplayMismatch,
};

mod budget;
mod mixed;

use budget::BudgetRead;

use super::super::witness::replay::WitnessCloseoutHistory;
pub(super) use mixed::scan_witness_closeout;

pub(super) fn replay(
	input: impl Read,
	owner: &RemoteDownloadOwnerRecord,
	max_bytes: u64,
	max_attempts: usize,
) -> Result<RemoteDownloadReplay, RemoteDownloadError> {
	scan(
		input,
		owner,
		ScanProfile::default(),
		max_bytes,
		max_attempts,
	)
}

pub(super) fn replay_with_bootstrap(
	input: impl Read,
	trust: &RemoteBootstrapTrust<'_>,
	max_bytes: u64,
	max_attempts: usize,
) -> Result<RemoteDownloadReplay, RemoteDownloadError> {
	scan(
		input,
		trust.owner(),
		ScanProfile {
			bootstrap: Some(trust),
			..ScanProfile::default()
		},
		max_bytes,
		max_attempts,
	)
}

pub(super) fn scan_finalization(
	input: impl Read,
	trust: &RemoteBootstrapTrust<'_>,
	history: &mut FinalizationHistory,
	retain_checkpoints: bool,
	max_bytes: u64,
	max_attempts: usize,
) -> Result<RemoteDownloadReplay, RemoteDownloadError> {
	scan(
		input,
		trust.owner(),
		ScanProfile {
			bootstrap: Some(trust),
			finalization: Some(history),
			retain_checkpoints,
			..ScanProfile::default()
		},
		max_bytes,
		max_attempts,
	)
}

pub(super) fn scan_continuation(
	input: impl Read,
	trust: &RemoteBootstrapTrust<'_>,
	history: &mut FinalizationHistory,
	continued: &mut ContinuedHistory,
	continuation_profile: ContinuationReplayProfile,
	max_bytes: u64,
	max_attempts: usize,
) -> Result<RemoteDownloadReplay, RemoteDownloadError> {
	scan(
		input,
		trust.owner(),
		ScanProfile {
			bootstrap: Some(trust),
			finalization: Some(history),
			continued: Some(continued),
			retain_checkpoints: true,
			continuation_profile,
			mixed: None,
		},
		max_bytes,
		max_attempts,
	)
}

#[derive(Default)]
struct ScanProfile<'scan, 'owner, 'qualification> {
	bootstrap: Option<&'scan RemoteBootstrapTrust<'owner>>,
	finalization: Option<&'scan mut FinalizationHistory>,
	continued: Option<&'scan mut ContinuedHistory>,
	mixed: Option<&'scan mut WitnessCloseoutHistory<'qualification>>,
	retain_checkpoints: bool,
	continuation_profile: ContinuationReplayProfile,
}

fn scan(
	input: impl Read,
	owner: &RemoteDownloadOwnerRecord,
	profile: ScanProfile<'_, '_, '_>,
	max_bytes: u64,
	max_attempts: usize,
) -> Result<RemoteDownloadReplay, RemoteDownloadError> {
	let ScanProfile {
		bootstrap,
		mut finalization,
		mut continued,
		mut mixed,
		retain_checkpoints,
		continuation_profile,
	} = profile;
	let manifest = owner.manifest();
	let validation = ReplayValidation {
		manifest,
		scope: manifest.scope.digest()?,
		context: RemoteDownloadContext::for_owner(owner),
		bootstrap,
		max_attempts,
	};
	let consumed = Cell::new(0);
	let limited = BudgetRead {
		input,
		consumed: &consumed,
		limit: max_bytes.saturating_add(1),
	};
	let mut reader = FrameReader::new(limited, ChainHead::start());
	let mut replay = RemoteDownloadReplay {
		boundary: RemoteReplayBoundary {
			head: ChainHead::start(),
			offset: 0,
		},
		job_prepared: None,
		stage_directory_prepared: None,
		attempts: Vec::new(),
		active_checkpoints: retain_checkpoints.then(Vec::new),
		uncertainty: None,
		logical_previous: None,
		issue: None,
	};

	loop {
		let mut budget_payload = None;
		let mut unsupported_kind = None;
		let mut selected_refusal = None;
		let read = reader.next_frame_with_payload_limit(|kind| {
			if mixed.is_none()
				&& continuation_profile == ContinuationReplayProfile::Witness
				&& continued
					.as_ref()
					.is_some_and(|history| history.active().is_some())
				&& !matches!(
					kind,
					FrameKind::RangeCheckpoint | FrameKind::FailureRecorded
				) {
				// The framed kind alone is sufficient to refuse a closeout or a
				// second continuation. Do not allocate or read its payload.
				unsupported_kind = Some(kind);
				return 0;
			}
			let selected_cap = if let Some(mixed) = mixed.as_ref() {
				match mixed::profile_cap(
					mixed,
					&replay,
					finalization.as_ref().map(|history| history.phase()),
					kind,
					max_attempts,
				) {
					Ok(cap) => cap,
					Err(issue) => {
						selected_refusal = Some(issue);
						return 0;
					}
				}
			} else {
				None
			};
			let profile_limit = if let Some(cap) = selected_cap {
				cap
			} else if bootstrap.is_some() && kind == FrameKind::StageDirectoryPrepared {
				MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES
			} else if continued.is_some() && kind == FrameKind::RemoteCaptureContinued {
				MAX_REMOTE_CONTINUATION_PAYLOAD_BYTES
			} else if finalization.is_some() && kind == FrameKind::RemoteCaptureRetired {
				MAX_REMOTE_RETIREMENT_BYTES
			} else if finalization.is_some() && is_finalization_kind(kind) {
				MAX_REMOTE_FINALIZATION_BYTES
			} else if finalization.is_some() {
				MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES
			} else {
				MAX_PAYLOAD_BYTES
			};
			if finalization.is_none() {
				return profile_limit;
			}

			// At this point the header has been read. Reserve its CRC and digest
			// before permitting any payload allocation or read.
			let available = max_bytes
				.saturating_sub(replay.boundary.offset)
				.saturating_sub(FRAME_OVERHEAD_BYTES as u64);
			budget_payload = Some(available);
			profile_limit.min(usize::try_from(available).unwrap_or(usize::MAX))
		});
		let over_budget = match (&read, budget_payload) {
			(
				Err(FrameReadError::Corrupt {
					problem: FrameProblem::PayloadTooLarge(length),
					..
				}),
				Some(available),
			) => u64::from(*length) > available,
			_ => false,
		};
		if consumed.get() > max_bytes || over_budget {
			replay.issue = Some(RemoteReplayIssue::SegmentLimit);
			break;
		}
		if let Some(issue) = selected_refusal {
			replay.issue = Some(issue);
			break;
		}
		if let Some(kind) = unsupported_kind {
			replay.issue = Some(RemoteReplayIssue::Record {
				offset: replay.boundary.offset,
				kind,
				problem: if mixed.as_ref().is_some_and(|history| history.uncertain())
					|| continued
						.as_ref()
						.is_some_and(|history| history.failure().is_some())
				{
					RemoteReplayMismatch::AfterUncertainty
				} else {
					RemoteReplayMismatch::UnsupportedKind
				},
			});
			break;
		}
		let frame = match read {
			Ok(Some(frame)) => frame,
			Ok(None) => {
				if replay.uncertainty.is_some()
					|| mixed.as_ref().is_some_and(|history| history.uncertain())
					|| continued
						.as_ref()
						.is_some_and(|history| history.failure().is_some())
					|| finalization.as_ref().is_some_and(|history| {
						history.phase() == RemoteFinalizationPhase::Uncertain
					}) {
					replay.issue = Some(RemoteReplayIssue::RecordedUncertainty);
				} else if bootstrap.is_some() && replay.stage_directory_prepared.is_none() {
					replay.issue = Some(RemoteReplayIssue::StageBootstrapMissing);
				}
				break;
			}
			Err(cause) => {
				replay.issue = Some(RemoteReplayIssue::Framing(cause));
				break;
			}
		};
		let end = RemoteReplayBoundary {
			head: frame.head(),
			offset: reader.offset(),
		};
		let kind = frame.kind();
		if continuation_profile == ContinuationReplayProfile::Witness {
			if replay.boundary.head.sequence().checked_add(1) != Some(end.head.sequence()) {
				replay.issue = Some(RemoteReplayIssue::Framing(FrameReadError::Corrupt {
					offset: replay.boundary.offset,
					problem: FrameProblem::Sequence(end.head.sequence()),
				}));
				break;
			}
			if kind == FrameKind::RemoteCaptureContinued && replay.attempts.len() >= max_attempts {
				replay.issue = Some(RemoteReplayIssue::AttemptLimit);
				break;
			}
		}
		let accepted = if let (Some(mixed), Some(continued), Some(legacy), Some(trust)) = (
			mixed.as_deref_mut(),
			continued.as_deref_mut(),
			finalization.as_deref_mut(),
			bootstrap,
		) {
			mixed::accept(
				mixed::Acceptance {
					mixed,
					continued,
					legacy,
					trust,
					validation: &validation,
				},
				&mut replay,
				frame,
				end,
			)
		} else if let (Some(continued), Some(trust), Some(history)) =
			(continued.as_deref_mut(), bootstrap, finalization.as_ref())
			&& (kind == FrameKind::RemoteCaptureContinued || continued.active().is_some())
		{
			continued
				.accept(&mut replay, history.phase(), trust, frame, end)
				.map_err(|problem| RemoteReplayIssue::Record {
					offset: replay.boundary.offset,
					kind,
					problem,
				})
		} else if let Some(history) = finalization.as_deref_mut() {
			accept_extended(&validation, &mut replay, history, owner, frame)
		} else {
			validation.accept(&mut replay, &frame)
		};
		if let Err(issue) = accepted {
			replay.issue = Some(issue);
			break;
		}
		replay.boundary = end;
	}
	Ok(replay)
}

fn is_finalization_kind(kind: FrameKind) -> bool {
	matches!(
		kind,
		FrameKind::StageSealed
			| FrameKind::VerificationRecorded
			| FrameKind::MetadataRecorded
			| FrameKind::PublishIntent
			| FrameKind::PublishObserved
			| FrameKind::DurabilityRecorded
			| FrameKind::ReceiptCommitted
	)
}

fn accept_extended(
	validation: &ReplayValidation<'_>,
	replay: &mut RemoteDownloadReplay,
	history: &mut FinalizationHistory,
	owner: &RemoteDownloadOwnerRecord,
	frame: Frame,
) -> Result<(), RemoteReplayIssue> {
	let kind = frame.kind();
	let offset = replay.boundary.offset;
	let mismatch = |problem| RemoteReplayIssue::Record {
		offset,
		kind,
		problem,
	};
	if kind == FrameKind::RemoteCaptureRetired {
		return history
			.accept_retirement(replay, owner, &frame)
			.map_err(mismatch);
	}
	if is_finalization_kind(kind) {
		return history.accept(replay, owner, frame).map_err(mismatch);
	}
	let admits_capture = history.phase() == RemoteFinalizationPhase::Capture
		|| (history.phase() == RemoteFinalizationPhase::Retired
			&& kind == FrameKind::RemoteStageAllocated);
	if !admits_capture {
		return Err(mismatch(RemoteReplayMismatch::Order));
	}
	validation.accept(replay, &frame)?;
	history.retain_capture(frame);
	Ok(())
}

struct ReplayValidation<'a> {
	manifest: &'a RemoteDownloadOwner,
	scope: RemoteScopeDigest,
	context: RemoteDownloadContext,
	bootstrap: Option<&'a RemoteBootstrapTrust<'a>>,
	max_attempts: usize,
}

impl ReplayValidation<'_> {
	fn accept(
		&self,
		replay: &mut RemoteDownloadReplay,
		frame: &Frame,
	) -> Result<(), RemoteReplayIssue> {
		use RemoteReplayMismatch as Mismatch;

		let mismatch = |problem| RemoteReplayIssue::Record {
			offset: replay.boundary.offset,
			kind: frame.kind(),
			problem,
		};
		if replay.uncertainty.is_some() {
			return Err(mismatch(Mismatch::AfterUncertainty));
		}
		if let Some(trust) = self.bootstrap {
			if frame.kind() == FrameKind::StageDirectoryPrepared {
				let job = replay
					.job_prepared
					.filter(|head| *head == replay.boundary.head)
					.ok_or_else(|| mismatch(Mismatch::Order))?;
				let directory = trust
					.admit_after_job(frame, job)
					.map_err(|cause| mismatch(Mismatch::Payload(cause)))?;
				replay.stage_directory_prepared = Some(directory);
				return Ok(());
			}
			if replay.job_prepared.is_some()
				&& replay.stage_directory_prepared.is_none()
				&& frame.kind() != FrameKind::JobPrepared
			{
				return Err(mismatch(Mismatch::BootstrapRequired));
			}
		}
		if !matches!(
			frame.kind(),
			FrameKind::JobPrepared
				| FrameKind::RemoteStageAllocated
				| FrameKind::EntryPrepared
				| FrameKind::RangeCheckpoint
				| FrameKind::FailureRecorded
		) {
			return Err(mismatch(Mismatch::UnsupportedKind));
		}
		let record = RemoteDownloadRecord::from_frame(frame)
			.map_err(|cause| mismatch(Mismatch::Payload(cause)))?;
		if record.context() != self.context {
			return Err(mismatch(Mismatch::Context));
		}
		if record.predecessor().unwrap_or_else(ChainHead::start) != replay.boundary.head {
			return Err(mismatch(Mismatch::Predecessor));
		}
		replay.accept(
			&record,
			frame.head(),
			self.manifest,
			self.scope,
			self.max_attempts,
		)
	}
}

#[cfg(test)]
mod tests;
