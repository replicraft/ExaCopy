use crate::frame::ChainHead;
use crate::remote_download::RemoteDownloadDestination;
use crate::remote_download::finalization::RemoteLocalMetadata;
use crate::remote_download::finalization_policy::SftpDataOnlyV1;
use crate::remote_download::replay::{
	RemotePreparedStage, RemoteReplayAttempt, RemoteReplayBoundary,
};
use crate::{StreamDigest, StreamLength};

use super::{
	Error, RemoteWitnessIntent, RemoteWitnessedCloseoutReplay, RemoteWitnessedReplayPhase as Phase,
};

impl RemoteWitnessedCloseoutReplay {
	/// Returns exact historical expectations for read-only assessment at clean kind 7.
	/// The journal declares the intention. It supplies no outcome or current capability.
	/// # Errors
	/// Refuses unclean, incomplete or differently phased evidence.
	pub fn publish_intent_inspection(&self) -> Result<RemoteWitnessedPublicExpectation<'_>, Error> {
		if self.issue().is_some() || self.phase() != Phase::PublishIntentRequiresObservation {
			return Err(Error::Binding);
		}
		self.public_expectation()
	}

	pub(super) fn public_expectation(&self) -> Result<RemoteWitnessedPublicExpectation<'_>, Error> {
		let witness = self.witness().ok_or(Error::FrameBinding)?;
		let binding = witness.binding();
		let attempt = self.attempts().last().ok_or(Error::FrameBinding)?;
		let stage = attempt.prepared().ok_or(Error::FrameBinding)?;
		let destination = self
			.history
			.publication_destination
			.as_ref()
			.ok_or(Error::FrameBinding)?;
		if attempt.allocation() != binding.allocation
			|| stage.head != binding.prepared()
			|| stage.file != binding.stage()
			|| stage.directory != witness.stage_directory
			|| destination.parent() != witness.target_parent
		{
			return Err(Error::Binding);
		}
		Ok(RemoteWitnessedPublicExpectation {
			boundary: self.boundary(),
			witness,
			stage,
			attempt,
			destination,
			digest: self
				.history
				.verified_stage_digest
				.ok_or(Error::FrameBinding)?,
			metadata: self.history.metadata.ok_or(Error::FrameBinding)?,
		})
	}
}

/// Existing authenticated scopes and exact historical expectations for a held read.
#[derive(Debug)]
#[must_use]
pub struct RemoteWitnessedPublicExpectation<'history> {
	boundary: RemoteReplayBoundary,
	witness: RemoteWitnessIntent,
	stage: RemotePreparedStage,
	attempt: &'history RemoteReplayAttempt,
	destination: &'history RemoteDownloadDestination,
	digest: StreamDigest,
	metadata: RemoteLocalMetadata,
}

impl RemoteWitnessedPublicExpectation<'_> {
	/// Returns the exact selected journal cut.
	pub const fn boundary(&self) -> RemoteReplayBoundary {
		self.boundary
	}
	/// Returns the original authenticated witness.
	pub const fn witness(&self) -> RemoteWitnessIntent {
		self.witness
	}
	/// Returns the original physical allocation head.
	pub const fn allocation(&self) -> ChainHead {
		self.attempt.allocation()
	}
	/// Returns the selected original private stage preparation.
	pub const fn stage(&self) -> RemotePreparedStage {
		self.stage
	}
	/// Returns the original private stage basename.
	pub fn stage_name(&self) -> &[u8] {
		self.attempt.name()
	}
	/// Returns the signed destination including exact raw target basename.
	pub const fn destination(&self) -> &RemoteDownloadDestination {
		self.destination
	}
	/// Returns the complete selected data extent.
	pub const fn extent(&self) -> StreamLength {
		self.witness.binding().coverage().end()
	}
	/// Returns the accepted kind-5 whole-stage BLAKE3 digest.
	pub const fn stage_digest(&self) -> StreamDigest {
		self.digest
	}
	/// Returns the accepted kind-6 UID and GID.
	pub const fn metadata(&self) -> RemoteLocalMetadata {
		self.metadata
	}
	/// Returns the fixed mode under the accepted metadata policy.
	pub const fn mode(&self) -> u16 {
		SftpDataOnlyV1::LOCAL_MODE
	}
}
