//! Historical retirement of a sealed remote capture before publication intent.

use std::io;

use exacopy_endpoint::{JournalFileBarrier, UnixComponent};

use crate::frame::{ChainHead, Frame, FrameKind, FrameWriter};
use crate::{LinuxFileIdentity, NamespaceObservation, SyncedFrame};

use super::finalization::RemotePublishTarget;
use super::{RemoteDownloadContext, RemoteDownloadError as Error, RemoteEpochs, RemoteScopeDigest};

mod wire;

/// Largest encoded retirement payload accepted at the framing boundary.
pub const MAX_REMOTE_RETIREMENT_BYTES: usize = 1_024;

/// Caller-observed identities and grant for a pre-intent restart.
///
/// Look up the exact allocated basename in the held private directory and
/// observe the same retained regular single-link stage there. Observe the
/// absent target under the same lease, authenticated grant and qualification.
/// This declaration does not hold, verify or authorize either native path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteRetirementObservation<'name> {
	/// Held private directory containing the retained capture.
	pub directory: LinuxFileIdentity,
	/// Exact allocated basename used for the held native stage observation.
	pub stage_name: UnixComponent<'name>,
	/// Retained stage identity observed at its exact allocated name.
	pub stage: LinuxFileIdentity,
	/// Independently held parent and selected application target.
	pub target: RemotePublishTarget<'name>,
	/// Fresh observation at the exact target under the current lease.
	pub target_observation: NamespaceObservation,
	/// Independently approved destination qualification digest.
	pub qualification_digest: [u8; 32],
	/// Exact authenticated current grant selected for this observation.
	pub grant_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RecordedRetirementObservation<'name> {
	pub(super) directory: LinuxFileIdentity,
	pub(super) stage: LinuxFileIdentity,
	pub(super) target: RemotePublishTarget<'name>,
	pub(super) qualification_digest: [u8; 32],
	pub(super) grant_digest: [u8; 32],
}

impl<'name> RemoteRetirementObservation<'name> {
	pub(super) fn recorded(self) -> Result<RecordedRetirementObservation<'name>, Error> {
		if self.target_observation != NamespaceObservation::Absent {
			return Err(Error::Binding);
		}
		Ok(RecordedRetirementObservation {
			directory: self.directory,
			stage: self.stage,
			target: self.target,
			qualification_digest: self.qualification_digest,
			grant_digest: self.grant_digest,
		})
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RetirementBinding {
	pub(super) context: RemoteDownloadContext,
	pub(super) scope: RemoteScopeDigest,
	pub(super) predecessor: ChainHead,
	pub(super) bootstrap: ChainHead,
	pub(super) allocation: ChainHead,
	pub(super) prepared: ChainHead,
	pub(super) seal: ChainHead,
	pub(super) epochs: RemoteEpochs,
}

/// A bounded declaration that retires a writer while preserving its sealed stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteCaptureRetired<'name> {
	binding: RetirementBinding,
	observation: RecordedRetirementObservation<'name>,
}

impl<'name> RemoteCaptureRetired<'name> {
	pub(super) fn new(
		binding: RetirementBinding,
		observation: RecordedRetirementObservation<'name>,
	) -> Result<Self, Error> {
		if binding.context.owner.as_bytes() == &[0; 32]
			|| binding.context.entry.as_bytes() == &[0; 16]
			|| binding.scope.as_bytes() == &[0; 32]
			|| observation.qualification_digest == [0; 32]
			|| observation.grant_digest == [0; 32]
			|| observation.directory == observation.stage
			|| [observation.directory, observation.stage].contains(&observation.target.parent)
			|| observation.directory.device() != observation.stage.device()
			|| observation.directory.device() != observation.target.parent.device()
		{
			return Err(Error::Binding);
		}
		if binding.bootstrap == ChainHead::start()
			|| binding.bootstrap.sequence() >= binding.allocation.sequence()
			|| binding.allocation.sequence().checked_add(1) != Some(binding.prepared.sequence())
			|| binding.prepared.sequence() >= binding.seal.sequence()
			|| binding.seal.sequence() > binding.predecessor.sequence()
			|| (binding.seal.sequence() == binding.predecessor.sequence()
				&& binding.seal != binding.predecessor)
			|| binding.predecessor.sequence().checked_add(1).is_none()
		{
			return Err(Error::FrameBinding);
		}
		Ok(Self {
			binding,
			observation,
		})
	}

	pub(super) const fn binding(self) -> RetirementBinding {
		self.binding
	}

	pub(super) const fn observation(self) -> RecordedRetirementObservation<'name> {
		self.observation
	}

	/// Returns the accepted history head this declaration would immediately follow.
	#[must_use]
	pub const fn predecessor(self) -> ChainHead {
		self.binding.predecessor
	}

	/// Encodes the complete canonical retirement declaration.
	///
	/// # Errors
	/// Refuses an encoding beyond the profile's fixed bound.
	pub fn encode(self) -> Result<Vec<u8>, Error> {
		wire::encode(self)
	}

	/// Decodes a canonical declaration. This supplies no authority over native objects.
	///
	/// # Errors
	/// Refuses malformed, noncanonical, oversized and unsupported bytes.
	pub fn decode(bytes: &'name [u8]) -> Result<Self, Error> {
		wire::decode(bytes)
	}

	/// Decodes the record and checks the exact immediately preceding frame.
	///
	/// # Errors
	/// Refuses a foreign kind, broken frame link, or invalid payload.
	pub fn from_frame(frame: &'name Frame) -> Result<Self, Error> {
		let record = Self::decode(frame.payload())?;
		let previous = record.predecessor();
		if frame.kind() != FrameKind::RemoteCaptureRetired
			|| previous.sequence().checked_add(1) != Some(frame.head().sequence())
			|| previous.digest() != frame.previous_digest()
		{
			return Err(Error::FrameBinding);
		}
		Ok(record)
	}

	fn exact_head(self) -> Result<ChainHead, Error> {
		FrameWriter::new(io::sink(), self.predecessor())
			.append(FrameKind::RemoteCaptureRetired, &self.encode()?)
			.map_err(|_| Error::FrameBinding)
	}
}

/// Retirement declaration matched against the selected read-only replay and live observations.
///
/// The caller must append through the same current held writer. This value
/// cannot create or modify either a native path or a journal.
#[derive(Debug)]
#[must_use]
pub struct RemoteRetirementCandidate<'name>(RemoteCaptureRetired<'name>);

impl<'name> RemoteRetirementCandidate<'name> {
	pub(super) const fn new(record: RemoteCaptureRetired<'name>) -> Self {
		Self(record)
	}

	/// Returns the exact declaration to write ahead of a fresh allocation.
	#[must_use]
	pub const fn record(&self) -> RemoteCaptureRetired<'name> {
		self.0
	}

	/// Consumes this candidate and validates the matching full file barrier.
	///
	/// Recheck the live lease and current grant before allocating. A matching
	/// acknowledgement alone does not establish current writer authority.
	///
	/// # Errors
	/// Refuses a different frame, payload, predecessor or barrier.
	pub fn validate_synced(self, synced: &SyncedFrame) -> Result<ChainHead, Error> {
		if synced.kind() != FrameKind::RemoteCaptureRetired
			|| synced.barrier() != JournalFileBarrier::SyncAll
			|| self.0.exact_head()? != synced.head()
		{
			return Err(Error::FrameBinding);
		}
		Ok(synced.head())
	}
}

/// Exact historical retirement boundary and old stage retained by replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteRetiredCapture {
	/// Accepted retirement frame.
	pub head: ChainHead,
	/// Exact old seal, which remains in the journal.
	pub seal: ChainHead,
	/// Old allocation retained in the capture inventory.
	pub allocation: ChainHead,
	/// Exact old physical preparation declaration.
	pub prepared: ChainHead,
	/// Historical native directory identity.
	pub directory: LinuxFileIdentity,
	/// Historical old stage inode, preserved by the transition.
	pub stage: LinuxFileIdentity,
	/// Grant digest recorded for independent current revalidation before allocation.
	pub grant_digest: [u8; 32],
	/// Destination qualification selected when the retirement was recorded.
	pub qualification_digest: [u8; 32],
}
