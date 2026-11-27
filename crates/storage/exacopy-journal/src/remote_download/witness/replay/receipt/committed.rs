use crate::frame::ChainHead;
use crate::remote_download::RemoteDownloadDestination;
use crate::remote_download::finalization::RemoteLocalMetadata;
use crate::remote_download::finalization_policy::SftpDataOnlyV1;
use crate::remote_download::replay::{
	RemotePreparedStage, RemoteReplayAttempt, RemoteReplayBoundary,
};
use crate::{StreamDigest, StreamLength};

use super::super::super::receipt_ready::{FINAL_NAME_BYTES, PENDING_NAME_BYTES, names};
use super::super::super::records::RemoteWitnessedOutcome;
use super::super::super::{Error, RemoteReceiptReady, RemoteWitnessIntent};
use super::super::{RemoteWitnessedCloseoutReplay, RemoteWitnessedReplayPhase as Phase};

impl RemoteWitnessedCloseoutReplay {
	/// Projects the exact historical facts needed to inspect a clean terminal kind 18.
	///
	/// Compare current receipt bytes using [Self::matches_committed_receipt].
	/// A projection carries no live authority or current namespace observations.
	///
	/// # Errors
	/// Refuses any other phase, unclean tail, or incomplete terminal evidence.
	pub fn committed_receipt_inspection(
		&self,
	) -> Result<RemoteCommittedReceiptInspection<'_>, Error> {
		if self.issue().is_some() || self.phase() != Phase::ReceiptCommitted {
			return Err(Error::Binding);
		}
		let witness = self.witness().ok_or(Error::FrameBinding)?;
		let binding = witness.binding();
		let stage_attempt = self.attempts().last().ok_or(Error::FrameBinding)?;
		let stage = stage_attempt.prepared().ok_or(Error::FrameBinding)?;
		let destination = self
			.history
			.committed_destination
			.as_ref()
			.ok_or(Error::FrameBinding)?;
		let outcome = self.observed_outcome().ok_or(Error::FrameBinding)?;
		if stage_attempt.allocation() != binding.allocation
			|| stage.head != binding.prepared()
			|| stage.file != binding.stage()
			|| stage.directory != witness.stage_directory
			|| destination.parent() != witness.target_parent
			|| !matches!(
				outcome,
				RemoteWitnessedOutcome::Submitted(_) | RemoteWitnessedOutcome::Recovered { .. }
			) {
			return Err(Error::Binding);
		}
		let (pending, final_name) = names(witness);
		Ok(RemoteCommittedReceiptInspection {
			boundary: self.boundary(),
			record: self.receipt_ready().ok_or(Error::FrameBinding)?,
			witness,
			stage,
			stage_attempt,
			destination,
			digest: self
				.history
				.verified_stage_digest
				.ok_or(Error::FrameBinding)?,
			metadata: self.history.metadata.ok_or(Error::FrameBinding)?,
			outcome,
			pending,
			final_name,
		})
	}
}

/// Read-only historical expectations for comparing the protected names and public file.
#[derive(Debug)]
#[must_use]
pub struct RemoteCommittedReceiptInspection<'history> {
	boundary: RemoteReplayBoundary,
	record: RemoteReceiptReady,
	witness: RemoteWitnessIntent,
	stage: RemotePreparedStage,
	stage_attempt: &'history RemoteReplayAttempt,
	destination: &'history RemoteDownloadDestination,
	digest: StreamDigest,
	metadata: RemoteLocalMetadata,
	outcome: RemoteWitnessedOutcome,
	pending: [u8; PENDING_NAME_BYTES],
	final_name: [u8; FINAL_NAME_BYTES],
}

impl RemoteCommittedReceiptInspection<'_> {
	/// Returns the exact accepted terminal kind-18 boundary.
	#[must_use]
	pub const fn boundary(&self) -> RemoteReplayBoundary {
		self.boundary
	}

	/// Returns the exact accepted kind 42, including the receipt inode, length and digest.
	#[must_use]
	pub const fn record(&self) -> RemoteReceiptReady {
		self.record
	}

	/// Returns the original authenticated witness and its protected name.
	#[must_use]
	pub const fn witness(&self) -> RemoteWitnessIntent {
		self.witness
	}

	/// Returns the active pass's original physical allocation head.
	#[must_use]
	pub const fn allocation(&self) -> ChainHead {
		self.stage_attempt.allocation()
	}

	/// Returns the original prepared head and private stage directory and file identities.
	#[must_use]
	pub const fn stage(&self) -> RemotePreparedStage {
		self.stage
	}

	/// Borrows the exact original private stage basename.
	#[must_use]
	pub fn stage_name(&self) -> &[u8] {
		self.stage_attempt.name()
	}

	/// Borrows the signed root, parent identity and exact destination basename.
	#[must_use]
	pub const fn destination(&self) -> &RemoteDownloadDestination {
		self.destination
	}

	/// Returns the exact complete extent from the authenticated witness and verified stage.
	#[must_use]
	pub const fn extent(&self) -> StreamLength {
		self.witness.binding().coverage().end()
	}

	/// Returns the accepted independent whole-stage BLAKE3 digest.
	#[must_use]
	pub const fn stage_digest(&self) -> StreamDigest {
		self.digest
	}

	/// Returns the local UID and GID accepted by kind 6.
	#[must_use]
	pub const fn metadata(&self) -> RemoteLocalMetadata {
		self.metadata
	}

	/// Returns the fixed mode accepted with the selected data-only metadata policy.
	#[must_use]
	pub const fn mode(&self) -> u16 {
		SftpDataOnlyV1::LOCAL_MODE
	}

	/// Returns the accepted positive live or recovered observation.
	#[must_use]
	pub const fn outcome(&self) -> RemoteWitnessedOutcome {
		self.outcome
	}

	/// Borrows the exact derived pending receipt basename.
	#[must_use]
	pub fn pending_name(&self) -> &[u8] {
		&self.pending
	}

	/// Borrows the exact derived final receipt basename.
	#[must_use]
	pub fn final_name(&self) -> &[u8] {
		&self.final_name
	}
}
