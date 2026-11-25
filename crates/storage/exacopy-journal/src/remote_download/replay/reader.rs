use std::cell::Cell;
use std::io::{self, Read};

use exacopy_endpoint::MAX_INTERRUPTED_RETRIES;

use crate::frame::{ChainHead, Frame, FrameKind, FrameReader, MAX_PAYLOAD_BYTES};

use super::super::{
	MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES, RemoteBootstrapTrust, RemoteDownloadContext,
	RemoteDownloadError, RemoteDownloadOwner, RemoteDownloadOwnerRecord, RemoteDownloadRecord,
	RemoteScopeDigest,
};
use super::{RemoteDownloadReplay, RemoteReplayBoundary, RemoteReplayIssue, RemoteReplayMismatch};

pub(super) fn replay(
	input: impl Read,
	owner: &RemoteDownloadOwnerRecord,
	max_bytes: u64,
	max_attempts: usize,
) -> Result<RemoteDownloadReplay, RemoteDownloadError> {
	scan(input, owner, None, max_bytes, max_attempts)
}

pub(super) fn replay_with_bootstrap(
	input: impl Read,
	trust: &RemoteBootstrapTrust<'_>,
	max_bytes: u64,
	max_attempts: usize,
) -> Result<RemoteDownloadReplay, RemoteDownloadError> {
	scan(input, trust.owner(), Some(trust), max_bytes, max_attempts)
}

fn scan(
	input: impl Read,
	owner: &RemoteDownloadOwnerRecord,
	bootstrap: Option<&RemoteBootstrapTrust<'_>>,
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
		let read = reader.next_frame_with_payload_limit(|kind| {
			if bootstrap.is_some() && kind == FrameKind::StageDirectoryPrepared {
				MAX_REMOTE_BOOTSTRAP_PAYLOAD_BYTES
			} else {
				MAX_PAYLOAD_BYTES
			}
		});
		if consumed.get() > max_bytes {
			replay.issue = Some(RemoteReplayIssue::SegmentLimit);
			break;
		}
		let frame = match read {
			Ok(Some(frame)) => frame,
			Ok(None) => {
				if replay.uncertainty.is_some() {
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
		if let Err(issue) = validation.accept(&mut replay, &frame) {
			replay.issue = Some(issue);
			break;
		}
		replay.boundary = RemoteReplayBoundary {
			head: frame.head(),
			offset: reader.offset(),
		};
	}
	Ok(replay)
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
