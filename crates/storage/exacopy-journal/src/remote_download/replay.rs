//! Bounded semantic inspection of a private remote-download segment with an authenticated owner.

use std::io::Read;

use crate::frame::{ChainHead, FrameKind, FrameReadError};
use crate::{LinuxFileIdentity, MAX_FIRST_SEGMENT_BYTES};

use super::{
	RemoteDownloadError, RemoteDownloadOwnerRecord, RemoteEpochs, RemoteUncertainBoundary,
};

mod attempts;
mod reader;

pub use attempts::RemoteReplayAttempt;

/// Maximum bytes of the supported first segment.
pub const MAX_REMOTE_REPLAY_SEGMENT_BYTES: u64 = MAX_FIRST_SEGMENT_BYTES;
/// Maximum retained fresh allocations in the supported first segment.
pub const MAX_REMOTE_REPLAY_ATTEMPTS: usize = 64;

/// Last frame boundary accepted by both integrity and remote semantic checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteReplayBoundary {
	/// Chain head, or the empty initial anchor.
	pub head: ChainHead,
	/// Segment-relative end offset in bytes.
	pub offset: u64,
}

/// Recorded local stage identities for one allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemotePreparedStage {
	/// Exact accepted EntryPrepared frame.
	pub head: ChainHead,
	/// Recorded fixed private stage directory identity.
	pub directory: LinuxFileIdentity,
	/// Recorded private stage file identity.
	pub file: LinuxFileIdentity,
}

/// A complete recorded failure whose physical effects still require observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteRecordedUncertainty {
	/// Exact accepted FailureRecorded frame.
	pub head: ChainHead,
	/// Active allocation or prepared stage frame named by that failure.
	pub attempt: ChainHead,
	/// Allocation and source epoch declared for the failed boundary.
	pub epochs: RemoteEpochs,
	/// The reported uncertain boundary.
	pub boundary: RemoteUncertainBoundary,
}

/// A framing-verified record disagreed with the authenticated remote history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteReplayMismatch {
	/// The remote payload's version, shape or structural frame links were refused.
	Payload(RemoteDownloadError),
	/// This kind does not belong to the private capture profile.
	UnsupportedKind,
	/// Owner, job or entry did not match the authenticated context.
	Context,
	/// The declared immediate predecessor did not equal the exact accepted head.
	Predecessor,
	/// First preparation declared a different immutable scope.
	Scope,
	/// The record appeared before its prerequisite or after an incompatible phase.
	Order,
	/// An allocation changed previous epochs, reused a name or nonce, or exceeded scope.
	Allocation,
	/// Stage binding named a different allocation, phase, nonce, or local identity.
	StageBinding,
	/// Checkpoint identity, ordinal, contiguous offset or end disagreed with the active pass.
	Checkpoint,
	/// Failure did not refer to the precise active phase.
	FailureBinding,
	/// A complete record followed latched uncertainty.
	AfterUncertainty,
}

/// Why the observed transcript requires read-only reconciliation.
#[derive(Debug)]
#[non_exhaustive]
pub enum RemoteReplayIssue {
	/// The first-segment limit was exceeded.
	SegmentLimit,
	/// No further allocation can be retained in this bounded profile.
	AttemptLimit,
	/// Incomplete, unsupported, corrupt or unreadable framing.
	Framing(FrameReadError),
	/// A complete frame was refused by semantic admission.
	Record {
		/// First byte of the refused frame.
		offset: u64,
		/// Kind from its integrity-checked frame.
		kind: FrameKind,
		/// Exact semantic condition that refused the frame.
		problem: RemoteReplayMismatch,
	},
	/// The final accepted frame recorded uncertainty.
	RecordedUncertainty,
}

/// Historical condition at the end of the accepted remote-download prefix.
#[derive(Debug)]
#[non_exhaustive]
pub enum RemoteReplayState<'scan> {
	/// No complete job preparation was observed.
	Empty,
	/// Only job preparation was accepted.
	JobPrepared,
	/// Latest fresh allocation has no accepted physical binding.
	AllocationUnbound,
	/// Latest allocation has an accepted local stage declaration.
	StageBound,
	/// The observed prefix requires independent reconciliation.
	ReconciliationRequired(&'scan RemoteReplayIssue),
}

/// Accepted historical evidence for read-only inspection of the private capture profile.
#[derive(Debug)]
pub struct RemoteDownloadReplay {
	boundary: RemoteReplayBoundary,
	job_prepared: Option<ChainHead>,
	attempts: Vec<RemoteReplayAttempt>,
	uncertainty: Option<RemoteRecordedUncertainty>,
	issue: Option<RemoteReplayIssue>,
}

impl RemoteDownloadReplay {
	/// Returns only the last semantically accepted frame boundary.
	#[must_use]
	pub const fn boundary(&self) -> RemoteReplayBoundary {
		self.boundary
	}

	/// Returns the exact accepted JobPrepared anchor, if any.
	#[must_use]
	pub const fn job_prepared(&self) -> Option<ChainHead> {
		self.job_prepared
	}

	/// Returns all accepted allocations in order, including superseded ones.
	#[must_use]
	pub fn attempts(&self) -> &[RemoteReplayAttempt] {
		&self.attempts
	}

	/// Returns a recorded failure even when a later frame also failed admission.
	#[must_use]
	pub const fn recorded_uncertainty(&self) -> Option<RemoteRecordedUncertainty> {
		self.uncertainty
	}

	/// Returns the history classification and any reconciliation reason.
	#[must_use]
	pub fn state(&self) -> RemoteReplayState<'_> {
		if let Some(issue) = &self.issue {
			return RemoteReplayState::ReconciliationRequired(issue);
		}
		match self.attempts.last() {
			Some(attempt) if attempt.prepared().is_some() => RemoteReplayState::StageBound,
			Some(_) => RemoteReplayState::AllocationUnbound,
			None if self.job_prepared.is_some() => RemoteReplayState::JobPrepared,
			None => RemoteReplayState::Empty,
		}
	}
}

/// Reads the selected first segment against a separately authenticated remote owner.
///
/// Supply the exact selected input at byte zero. The result reports historical
/// evidence, while current names, inode provenance, bytes, leases, and authority
/// remain the responsibility of the application. Read and format failures
/// retain the accepted prefix in the returned reconciliation state.
/// The scan retains at most 64 allocation summaries and one bounded frame at
/// a time. Each allocation allows at most 4,096 contiguous checkpoints.
///
/// # Errors
/// Fails if the owner's immutable canonical scope digest cannot be computed.
pub fn replay_remote_download(
	input: impl Read,
	owner: &RemoteDownloadOwnerRecord,
) -> Result<RemoteDownloadReplay, RemoteDownloadError> {
	reader::replay(
		input,
		owner,
		MAX_REMOTE_REPLAY_SEGMENT_BYTES,
		MAX_REMOTE_REPLAY_ATTEMPTS,
	)
}
