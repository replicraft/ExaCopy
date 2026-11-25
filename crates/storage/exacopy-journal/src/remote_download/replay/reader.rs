use std::cell::Cell;
use std::io::{self, Read};

use exacopy_endpoint::MAX_INTERRUPTED_RETRIES;

use crate::frame::{ChainHead, FrameKind, FrameReader};

use super::super::{
	RemoteDownloadContext, RemoteDownloadError, RemoteDownloadOwnerRecord, RemoteDownloadRecord,
};
use super::{RemoteDownloadReplay, RemoteReplayBoundary, RemoteReplayIssue, RemoteReplayMismatch};

pub(super) fn replay(
	input: impl Read,
	owner: &RemoteDownloadOwnerRecord,
	max_bytes: u64,
	max_attempts: usize,
) -> Result<RemoteDownloadReplay, RemoteDownloadError> {
	let manifest = owner.manifest();
	let expected_scope = manifest.scope.digest()?;
	let expected_context = RemoteDownloadContext {
		owner: owner.digest(),
		job: manifest.job,
		entry: manifest.scope.entry,
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
		attempts: Vec::new(),
		uncertainty: None,
		issue: None,
	};

	loop {
		let read = reader.next_frame();
		if consumed.get() > max_bytes {
			replay.issue = Some(RemoteReplayIssue::SegmentLimit);
			break;
		}
		let frame = match read {
			Ok(Some(frame)) => frame,
			Ok(None) => {
				if replay.uncertainty.is_some() {
					replay.issue = Some(RemoteReplayIssue::RecordedUncertainty);
				}
				break;
			}
			Err(cause) => {
				replay.issue = Some(RemoteReplayIssue::Framing(cause));
				break;
			}
		};
		let mismatch = |problem| RemoteReplayIssue::Record {
			offset: replay.boundary.offset,
			kind: frame.kind(),
			problem,
		};
		if replay.uncertainty.is_some() {
			replay.issue = Some(mismatch(RemoteReplayMismatch::AfterUncertainty));
			break;
		}
		if !matches!(
			frame.kind(),
			FrameKind::JobPrepared
				| FrameKind::RemoteStageAllocated
				| FrameKind::EntryPrepared
				| FrameKind::RangeCheckpoint
				| FrameKind::FailureRecorded
		) {
			replay.issue = Some(mismatch(RemoteReplayMismatch::UnsupportedKind));
			break;
		}
		let record = match RemoteDownloadRecord::from_frame(&frame) {
			Ok(record) => record,
			Err(cause) => {
				replay.issue = Some(mismatch(RemoteReplayMismatch::Payload(cause)));
				break;
			}
		};
		if record.context() != expected_context {
			replay.issue = Some(mismatch(RemoteReplayMismatch::Context));
			break;
		}
		if record.predecessor().unwrap_or_else(ChainHead::start) != replay.boundary.head {
			replay.issue = Some(mismatch(RemoteReplayMismatch::Predecessor));
			break;
		}
		if let Err(issue) = replay.accept(
			&record,
			frame.head(),
			manifest,
			expected_scope,
			max_attempts,
		) {
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
