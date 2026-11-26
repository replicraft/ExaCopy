use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_publication::{PublicationFailure, ReceiptWorkspace};
use exacopy_journal::frame::{ChainHead, Frame, FrameKind};
use exacopy_journal::remote_download::finalization::RemoteLocalMetadata;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::{RemoteDownloadContext, RemoteScopeDigest};
use exacopy_journal::{LinuxFileIdentity, SyncedFrame};
use exacopy_model::{CopyBinding, PublishNoClobber};

use crate::remote_resume::TargetState;

/// Immutable authority selected independently of the signed job document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemotePublicationAuthority {
	/// Exact signed remote scope admitted by the current grant.
	pub scope: RemoteScopeDigest,
	/// Digest of the independently verified active grant.
	pub grant: [u8; 32],
	/// Digest of an independently provisioned native destination qualification.
	pub qualification: [u8; 32],
	/// Actual held directory identity checked by that qualification.
	pub parent: LinuxFileIdentity,
}

/// Current authority and namespace observation before an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentRemoteAuthority {
	/// Grant, scope and qualification re-established for this attempt.
	pub binding: RemotePublicationAuthority,
	/// Actual observation of the signed target under the held destination.
	pub target: TargetState,
}

/// Revalidates the active local authorization and destination qualification.
pub trait RemoteAuthorityCheck {
	/// Failure to confirm current authority and filesystem observations.
	type Error;

	/// Checks scope, grant expiration and revocation, qualification and target.
	///
	/// # Errors
	/// Refuses unknown or stale authority, qualification or held observations.
	fn recheck(&mut self) -> Result<CurrentRemoteAuthority, Self::Error>;
}

/// Immutable facts of the held stage after selected-stream metadata validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteReadyStageFacts {
	/// Model binding of the one native operation.
	pub binding: CopyBinding,
	/// Actual held stage file.
	pub stage: LinuxFileIdentity,
	/// Actual private stage directory.
	pub directory: LinuxFileIdentity,
	/// Actual held destination parent.
	pub parent: LinuxFileIdentity,
	/// Exact verified logical length.
	pub length: u64,
	/// Ordinary permission bits observed on the held and named stage.
	pub mode: u16,
	/// Verified native UID and GID.
	pub metadata: RemoteLocalMetadata,
}

/// Actual names fixed in the held native stage capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteStageNames<'held> {
	/// Private name authorized by StageAllocated.
	pub stage: UnixComponent<'held>,
	/// Public name bound to the no-replace operation.
	pub target: UnixComponent<'held>,
}

/// Exact physical and logical location of the held native stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteStageLocation<'held> {
	/// Model binding of the exact job, entry, run and stage nonce.
	pub binding: CopyBinding,
	/// Actual held stage file.
	pub stage: LinuxFileIdentity,
	/// Actual private stage directory.
	pub directory: LinuxFileIdentity,
	/// Actual held destination parent.
	pub parent: LinuxFileIdentity,
	/// Raw validated names fixed by the held native capability.
	pub names: RemoteStageNames<'held>,
}

impl RemoteReadyStageFacts {
	pub(super) const fn location(self, names: RemoteStageNames<'_>) -> RemoteStageLocation<'_> {
		RemoteStageLocation {
			binding: self.binding,
			stage: self.stage,
			directory: self.directory,
			parent: self.parent,
			names,
		}
	}
}

/// Exact synchronized intent and active authorization supplied to the native grant fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemotePublicationFence {
	pub(super) context: RemoteDownloadContext,
	pub(super) authority: RemotePublicationAuthority,
	pub(super) intent: ChainHead,
}

impl RemotePublicationFence {
	/// Returns the signed job, owner and entry.
	#[must_use]
	pub const fn context(self) -> RemoteDownloadContext {
		self.context
	}

	/// Returns the scope, grant, qualification and physical destination binding.
	#[must_use]
	pub const fn authority(self) -> RemotePublicationAuthority {
		self.authority
	}

	/// Returns the exact confirmed synchronized native publication intent.
	#[must_use]
	pub const fn intent(self) -> ChainHead {
		self.intent
	}
}

/// The receipt capability for the same authorized private job.
pub trait RemoteReceiptWorkspace: ReceiptWorkspace {
	/// Revalidates the exact signed native job directory before using the workspace.
	///
	/// # Errors
	/// Refuses changed identity or unavailable held namespace evidence.
	fn check_job(&self, expected: LinuxFileIdentity) -> Result<(), Self::Error>;
}

/// Successful native publication after all required barriers and rechecks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemotePublicationFacts {
	/// Target observation after barriers, with the old private name absent.
	pub target: LinuxFileIdentity,
	/// Private directory whose namespace barrier completed.
	pub directory: LinuxFileIdentity,
	/// Destination parent whose namespace barrier completed.
	pub parent: LinuxFileIdentity,
}

/// Transition from the independently measured capture stage to local readiness.
pub trait RemoteFinalizationStage {
	/// Failure to check actual local readiness or to perform publication.
	type Error;
	/// The same stage after verified data-only metadata and full file sync.
	type Ready: RemoteReadyStage<Error = Self::Error>;

	/// Read-only observation of the actual held stage, directory, destination and names.
	///
	/// This operation performs no metadata mutation, file sync or namespace effect.
	///
	/// # Errors
	/// Refuses changed or unavailable observations of the held and named objects.
	fn inspect_location(&self) -> Result<RemoteStageLocation<'_>, Self::Error>;

	/// Checks stage identity, exact extent, EOF policy, mode, owner, attributes and fsync.
	///
	/// This consumes the original held stage. Revalidate its inspected identity and
	/// location before the metadata barrier. Preserve it if any check fails.
	///
	/// # Errors
	/// Refuses changed, unsupported or unconfirmed evidence. Preserve the held stage.
	fn prepare_metadata(self, length: u64) -> Result<Self::Ready, Self::Error>;
}

/// One metadata-ready exact stage under the original job and destination lease.
pub trait RemoteReadyStage {
	/// Failure to re-establish facts or complete the exclusive publication.
	type Error;

	/// Returns the names bound by the held stage location.
	fn names(&self) -> RemoteStageNames<'_>;

	/// Revalidates the same held object, complete metadata and unchanged verified bytes.
	///
	/// # Errors
	/// Refuses unavailable or mismatched observations.
	fn recheck(&self) -> Result<RemoteReadyStageFacts, Self::Error>;

	/// Consumes the exact model permit and uses the native one-shot no-replace primitive.
	///
	/// The adapter completes its potentially blocking native readiness and qualification
	/// checks, then acquires current grant serialization for the exact fence. It checks
	/// revocation and the monotonic deadline at that gate and holds the guard through
	/// the immediate rename syscall with no intervening I/O. It checks the resulting
	/// public inode and old name before returning success after both directory barriers.
	///
	/// # Errors
	/// Distinguishes a known incumbent from outcomes requiring reconciliation.
	fn publish(
		self,
		permit: PublishNoClobber,
		fence: RemotePublicationFence,
	) -> Result<RemotePublicationFacts, PublicationFailure<Self::Error>>;
}

/// One exclusively held first-segment writer with independent exact read-back.
pub trait RemoteFinalizationJournal {
	/// Failure to establish the current frame boundary or its durable successor.
	type Error;

	/// Returns the independently confirmed current held segment boundary.
	///
	/// # Errors
	/// Refuses if namespace, physical segment or accepted boundary cannot be checked.
	fn boundary(&mut self) -> Result<RemoteReplayBoundary, Self::Error>;

	/// Synchronizes one exact successor after comparing the actual predecessor.
	///
	/// # Errors
	/// Refuses a different head or offset before writing. A write or barrier error
	/// preserves bytes and requires the adapter to retire the uncertain writer.
	fn append(
		&mut self,
		expected: RemoteReplayBoundary,
		kind: FrameKind,
		payload: Vec<u8>,
	) -> Result<(Frame, SyncedFrame), Self::Error>;
}
