use std::cell::Cell;
use std::io::{self, Read};

use exacopy_endpoint::MAX_INTERRUPTED_RETRIES;

use crate::frame::{
	ChainHead, FRAME_OVERHEAD_BYTES, Frame, FrameKind, FrameProblem, FrameReadError, FrameReader,
	MAX_PAYLOAD_BYTES,
};

use super::super::finalization::MAX_REMOTE_FINALIZATION_BYTES;
use super::super::finalization_replay::{FinalizationHistory, RemoteFinalizationPhase};
use super::super::retirement::MAX_REMOTE_RETIREMENT_BYTES;
use super::super::{
	MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES, MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES, RemoteBootstrapTrust,
	RemoteDownloadContext, RemoteDownloadError, RemoteDownloadOwner, RemoteDownloadOwnerRecord,
	RemoteDownloadRecord, RemoteScopeDigest,
};
use super::{RemoteDownloadReplay, RemoteReplayBoundary, RemoteReplayIssue, RemoteReplayMismatch};

pub(super) fn replay(
	input: impl Read,
	owner: &RemoteDownloadOwnerRecord,
	max_bytes: u64,
	max_attempts: usize,
) -> Result<RemoteDownloadReplay, RemoteDownloadError> {
	scan(input, owner, None, None, max_bytes, max_attempts)
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
		Some(trust),
		None,
		max_bytes,
		max_attempts,
	)
}

pub(super) fn scan_finalization(
	input: impl Read,
	trust: &RemoteBootstrapTrust<'_>,
	history: &mut FinalizationHistory,
	max_bytes: u64,
	max_attempts: usize,
) -> Result<RemoteDownloadReplay, RemoteDownloadError> {
	scan(
		input,
		trust.owner(),
		Some(trust),
		Some(history),
		max_bytes,
		max_attempts,
	)
}

fn scan(
	input: impl Read,
	owner: &RemoteDownloadOwnerRecord,
	bootstrap: Option<&RemoteBootstrapTrust<'_>>,
	mut finalization: Option<&mut FinalizationHistory>,
	max_bytes: u64,
	max_attempts: usize,
) -> Result<RemoteDownloadReplay, RemoteDownloadError> {
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
		uncertainty: None,
		issue: None,
	};

	loop {
		let mut budget_payload = None;
		let read = reader.next_frame_with_payload_limit(|kind| {
			let profile_limit = if bootstrap.is_some() && kind == FrameKind::StageDirectoryPrepared
			{
				MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES
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
		let frame = match read {
			Ok(Some(frame)) => frame,
			Ok(None) => {
				if replay.uncertainty.is_some()
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
		let head = frame.head();
		let accepted = if let Some(history) = finalization.as_deref_mut() {
			accept_extended(&validation, &mut replay, history, owner, frame)
		} else {
			validation.accept(&mut replay, &frame)
		};
		if let Err(issue) = accepted {
			replay.issue = Some(issue);
			break;
		}
		replay.boundary = RemoteReplayBoundary {
			head,
			offset: reader.offset(),
		};
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

struct BudgetRead<'budget, R> {
	input: R,
	consumed: &'budget Cell<u64>,
	limit: u64,
}

impl<R: Read> Read for BudgetRead<'_, R> {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		let remaining = self
			.limit
			.checked_sub(self.consumed.get())
			.ok_or_else(|| io::Error::other("remote journal byte budget exceeded"))?;
		let limit = usize::try_from(remaining)
			.unwrap_or(buffer.len())
			.min(buffer.len());
		if limit == 0 {
			return Ok(0);
		}
		let mut interruptions = 0;
		loop {
			match self.input.read(&mut buffer[..limit]) {
				Ok(count) if count <= limit => {
					let count_u64 = u64::try_from(count).map_err(io::Error::other)?;
					let consumed =
						self.consumed.get().checked_add(count_u64).ok_or_else(|| {
							io::Error::other("remote journal byte offset overflow")
						})?;
					self.consumed.set(consumed);
					return Ok(count);
				}
				Ok(_) => {
					return Err(io::Error::new(
						io::ErrorKind::InvalidData,
						"remote journal reader returned an oversized count",
					));
				}
				Err(cause) if cause.kind() == io::ErrorKind::Interrupted => {
					if interruptions >= MAX_INTERRUPTED_RETRIES {
						return Err(io::Error::other(cause));
					}
					interruptions += 1;
				}
				Err(cause) => return Err(cause),
			}
		}
	}
}

#[cfg(test)]
mod tests;
