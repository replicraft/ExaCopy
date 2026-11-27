use crate::frame::ChainHead;
use crate::remote_download::RemoteDownloadDestination;
use crate::remote_download::finalization::RemoteLocalMetadata;
use crate::remote_download::replay::{RemotePreparedStage, RemoteReplayBoundary};
use crate::{StreamDigest, StreamLength};

use super::super::super::receipt_ready::{FINAL_NAME_BYTES, PENDING_NAME_BYTES, names};
use super::super::super::records::RemoteWitnessedOutcome;
use super::super::super::{Error, RemoteReceiptReady, RemoteWitnessIntent};
use super::super::{
	RemoteWitnessedCloseoutReplay, RemoteWitnessedPublicExpectation,
	RemoteWitnessedReplayPhase as Phase,
};

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
		let publication = self.public_expectation()?;
		let outcome = self.observed_outcome().ok_or(Error::FrameBinding)?;
		if !matches!(
			outcome,
			RemoteWitnessedOutcome::Submitted(_) | RemoteWitnessedOutcome::Recovered { .. }
		) {
			return Err(Error::Binding);
		}
		let (pending, final_name) = names(publication.witness());
		Ok(RemoteCommittedReceiptInspection {
			publication,
			record: self.receipt_ready().ok_or(Error::FrameBinding)?,
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
	publication: RemoteWitnessedPublicExpectation<'history>,
	record: RemoteReceiptReady,
	outcome: RemoteWitnessedOutcome,
	pending: [u8; PENDING_NAME_BYTES],
	final_name: [u8; FINAL_NAME_BYTES],
}

impl RemoteCommittedReceiptInspection<'_> {
	/// Returns the public file expectation independently of the receipt declaration.
	#[must_use]
	pub const fn publication(&self) -> &RemoteWitnessedPublicExpectation<'_> {
		&self.publication
	}

	/// Returns the exact accepted terminal kind-18 boundary.
	#[must_use]
	pub const fn boundary(&self) -> RemoteReplayBoundary {
		self.publication.boundary()
	}

	/// Returns the exact accepted kind 42, including the receipt inode, length and digest.
	#[must_use]
	pub const fn record(&self) -> RemoteReceiptReady {
		self.record
	}

	/// Returns the original authenticated witness and its protected name.
	#[must_use]
	pub const fn witness(&self) -> RemoteWitnessIntent {
		self.publication.witness()
	}

	/// Returns the active pass's original physical allocation head.
	#[must_use]
	pub const fn allocation(&self) -> ChainHead {
		self.publication.allocation()
	}

	/// Returns the original prepared head and private stage directory and file identities.
	#[must_use]
	pub const fn stage(&self) -> RemotePreparedStage {
		self.publication.stage()
	}

	/// Borrows the exact original private stage basename.
	#[must_use]
	pub fn stage_name(&self) -> &[u8] {
		self.publication.stage_name()
	}

	/// Borrows the signed root, parent identity and exact destination basename.
	#[must_use]
	pub const fn destination(&self) -> &RemoteDownloadDestination {
		self.publication.destination()
	}

	/// Returns the exact complete extent from the authenticated witness and verified stage.
	#[must_use]
	pub const fn extent(&self) -> StreamLength {
		self.publication.extent()
	}

	/// Returns the accepted independent whole-stage BLAKE3 digest.
	#[must_use]
	pub const fn stage_digest(&self) -> StreamDigest {
		self.publication.stage_digest()
	}

	/// Returns the local UID and GID accepted by kind 6.
	#[must_use]
	pub const fn metadata(&self) -> RemoteLocalMetadata {
		self.publication.metadata()
	}

	/// Returns the fixed mode accepted with the selected data-only metadata policy.
	#[must_use]
	pub const fn mode(&self) -> u16 {
		self.publication.mode()
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
