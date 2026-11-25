use exacopy_journal::frame::ChainHead;
use exacopy_journal::remote_download::RemoteStageDirectoryPrepared;
use exacopy_journal::{JournalEntryId, JournalEpoch, JournalJobId, OwnerDigest};

use crate::remote_capture::{CaptureCheckpoints, SourceEpoch};

/// Digest of the locally approved source and destination scope for a remote job.
///
/// The authority owner covers the route, authenticated SSH authority, remote
/// root and raw path, destination root and target, limits and requested policy.
/// A remote byte manifest is unnecessary. The digest supplies neither authority
/// nor a stable source-object identity by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteScopeDigest([u8; 32]);

impl RemoteScopeDigest {
	/// Wraps the digest produced by the application authority owner.
	#[must_use]
	pub const fn from_bytes(bytes: [u8; 32]) -> Self {
		Self(bytes)
	}

	/// Returns the bytes for the application journal's exact scope binding.
	#[must_use]
	pub const fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}
}

/// The authorized job and entry whose private state may be resumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeScope {
	/// Persisted job ID from the same owner-controlled job.
	pub job: JournalJobId,
	/// Entry selected by both replay and current authorization.
	pub entry: JournalEntryId,
	/// Digest of the authenticated owner record accepted by the caller.
	pub owner: OwnerDigest,
	/// Digest of the approved endpoint and policy binding.
	pub approved_scope: RemoteScopeDigest,
	/// Maximum bytes allowed for this entry by the grant.
	pub maximum_length: u64,
}

/// The prior or next physical private stage and its generation labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureAttempt<B> {
	/// Run generation of the durable job.
	pub run: JournalEpoch,
	/// Unique held read pass, including for a reopened live remote source.
	pub source: SourceEpoch,
	/// Identity of the actual local private regular file, independent of its name.
	pub stage: B,
}

/// The publication state established by authenticated read-only replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReplayState {
	/// The complete supported journal ends before any publication intent.
	CleanBeforeIntent,
	/// Intent was recorded, so the public effect may have been attempted.
	IntentRecorded,
	/// Replay recognized a completed publication, so fresh restart is inappropriate.
	Published,
	/// An incompatible, torn, or otherwise uncertain record prevents safe restart.
	Uncertain,
}

/// Selected historical boundary that immediately precedes the first allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationBase {
	/// Historical marker for the pre-bootstrap format, used by legacy fixtures.
	///
	/// A native writable application must require the signed stage-directory profile.
	LegacyJobPrepared(ChainHead),
	/// Verified signed stage-directory proof from the selected strict replay.
	SignedStageDirectoryPrepared(RemoteStageDirectoryPrepared),
}

impl AllocationBase {
	/// Returns the exact record head immediately before any allocation existed.
	#[must_use]
	pub const fn head(self) -> ChainHead {
		match self {
			Self::LegacyJobPrepared(head) => head,
			Self::SignedStageDirectoryPrepared(proof) => proof.head(),
		}
	}
}

/// Exact durable allocation and the consumed run and source epochs it declares.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocatedCapture {
	/// Journal anchor of the accepted private filename allocation.
	pub head: ChainHead,
	/// Run generation declared by the allocation.
	pub run: JournalEpoch,
	/// Live source pass reserved by the allocation.
	pub source: SourceEpoch,
}

/// Selected replay and fresh allocation for one existing remote job under its lease.
///
/// The application authenticates the job owner, selects its complete journal under
/// the exclusive lease, and preserves all prior allocations and private material.
/// An unbound allocation in a recovered prefix still consumes its epochs. The
/// application cannot infer absence from missing stage identity or adopt an orphan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeHistory<B> {
	/// Exact scope of the persisted job and entry.
	pub scope: ResumeScope,
	/// Authenticated anchor of the explicitly selected bootstrap profile.
	pub allocation_base: AllocationBase,
	/// Last accepted complete frame of that job, rechecked in the held writer.
	pub predecessor: ChainHead,
	/// Last recorded physical stage from before the pending allocation, if any.
	pub previous: Option<CaptureAttempt<B>>,
	/// Latest consumed allocation before `pending_allocation`, including unbound attempts.
	pub previous_allocation: Option<AllocatedCapture>,
	/// Fresh allocation synchronized by the current operation before creating its stage.
	///
	/// An unbound allocation found after a restart belongs in the consumed history.
	pub pending_allocation: AllocatedCapture,
	/// Actual immediate predecessor established by the synchronized allocation append.
	///
	/// The application confirms the encoded predecessor's sequence and digest
	/// against the held writer's exact prior head before creating the stage.
	pub pending_allocation_predecessor: ChainHead,
	/// Whether journal replay permits pre-intent restart.
	pub state: ReplayState,
}

/// Current read-only observation of the authorized public destination name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetState {
	/// The name was absent in the bound destination directory.
	Absent,
	/// An incumbent occupies the name and must be preserved.
	Occupied,
	/// The directory, object identity, or name outcome could not be checked.
	Unknown,
}

/// Fresh authority and observations supplied for one restart request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartAdmission {
	/// Scope reauthorized for the destination and the same remote authority.
	pub scope: ResumeScope,
	/// A strictly later read pass on an authenticated held source.
	pub source: SourceEpoch,
	/// The destination's current read-only observation for `scope`.
	pub target: TargetState,
}

/// A new attempt bound to the exact owner-controlled predecessor and stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartRecord<B> {
	/// The authorized scope carried forward by this restart.
	pub scope: ResumeScope,
	/// Exact synchronized pending allocation, including digest and frame sequence.
	pub predecessor: ChainHead,
	/// The last earlier physical stage whose material is retained, when one was bound.
	pub previous: Option<CaptureAttempt<B>>,
	/// The new private stage and held live pass.
	pub next: CaptureAttempt<B>,
	/// Length freshly observed on the new live pass.
	pub length: u64,
}

/// The application journal owner's confirmed successor after applicable barriers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncedRestart<B> {
	/// Exact record that was appended against its recorded predecessor.
	pub record: RestartRecord<B>,
	/// The accepted successor chain head established by the writer.
	pub head: ChainHead,
}

/// A held job ledger which synchronizes restart and subsequent checkpoint records.
pub trait RestartJournal<B>: CaptureCheckpoints<B> {
	/// Commits the requested restart against its exact predecessor under the lease.
	///
	/// # Errors
	/// Fails if the prior head, lease, record, stage ownership, or required barriers
	/// cannot be confirmed. The adapter establishes the exact current predecessor
	/// and required creation and namespace barriers before returning a confirmed
	/// successor. An error may leave a partial record and requires read-only replay.
	/// Subsequent checkpoint appends stay bound to the committed restart and lease.
	fn sync_restart(&mut self, record: RestartRecord<B>) -> Result<SyncedRestart<B>, Self::Error>;
}
