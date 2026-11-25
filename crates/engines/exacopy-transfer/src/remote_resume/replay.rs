use exacopy_journal::frame::ChainHead;
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

/// Authenticated replay of one existing remote job under its exclusive lease.
///
/// Only the application journal owner can establish authenticity, boundary
/// completeness and current lease ownership. A clean prefix within a torn
/// journal is still uncertain. A pre-create orphan with no recorded physical
/// stage must be preserved and reconciled outside this restart path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeHistory<B> {
	/// Exact scope of the persisted job and entry.
	pub scope: ResumeScope,
	/// Last accepted complete frame of that job.
	pub predecessor: ChainHead,
	/// Last known stage and read pass, preserved if restart is admitted.
	pub previous: CaptureAttempt<B>,
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
	/// Exact previous chain head, including digest and frame sequence.
	pub predecessor: ChainHead,
	/// The earlier private attempt whose material is retained.
	pub previous: CaptureAttempt<B>,
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
