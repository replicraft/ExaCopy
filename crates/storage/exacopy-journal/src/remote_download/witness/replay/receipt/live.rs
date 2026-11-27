use crate::LinuxFileIdentity;
use crate::frame::FrameKind;
use crate::remote_download::RemoteDownloadContext;

use super::super::super::records::{
	RemoteWitnessCloseoutBody as Body, RemoteWitnessedOutcome as Outcome,
};
use super::super::prepublication::{PreparedWitnessedCloseout, prepare_frame, prepare_payload};
use super::super::{
	Error, RemoteBootstrapTrust, RemoteReceiptReady, RemoteWitnessIntent,
	RemoteWitnessedCloseoutReplay, RemoteWitnessedReplayPhase as Phase,
};

impl RemoteWitnessedCloseoutReplay {
	/// Prepares kind 42 for the sealed pending receipt of this exact live publication.
	///
	/// The caller establishes the original reserved inode, canonical bytes and
	/// required native file and directory barriers under current authority.
	///
	/// # Errors
	/// Refuses a different owner or witness, a non-live or unclean kind-9 cut,
	/// or an inode that aliases the selected directories or any prepared stage.
	pub fn prepare_live_receipt_ready(
		&self,
		trust: &RemoteBootstrapTrust<'_>,
		witness: RemoteWitnessIntent,
		receipt: LinuxFileIdentity,
	) -> Result<PreparedWitnessedCloseout, Error> {
		check_live_owner(self, trust, witness)?;
		let basis = self.durable_receipt_basis()?;
		let expectation = basis.receipt_ready_expectation(receipt)?;
		let payload = RemoteReceiptReady::encode(&expectation)?;
		prepare_payload(basis.boundary(), FrameKind::RemoteReceiptReady, &payload)
	}

	/// Prepares kind 18 for the exact promoted receipt selected by clean kind 42.
	///
	/// The caller confirms exclusive promotion, canonical bytes, pending-name
	/// absence and required native barriers under current authority.
	///
	/// # Errors
	/// Refuses a different owner, witness or kind-42 record, or non-live replay.
	pub fn prepare_live_receipt_commit(
		&self,
		trust: &RemoteBootstrapTrust<'_>,
		witness: RemoteWitnessIntent,
		ready: RemoteReceiptReady,
	) -> Result<PreparedWitnessedCloseout, Error> {
		check_live_owner(self, trust, witness)?;
		let inspected = self.receipt_ready_inspection()?;
		if inspected.record() != ready {
			return Err(Error::Binding);
		}
		prepare_frame(
			witness.binding(),
			inspected.boundary(),
			Body::CommittedReceipt {
				digest: ready.digest(),
				inode: ready.receipt(),
			},
		)
	}
}

impl PreparedWitnessedCloseout {
	/// Confirms the exact live kind-42 proposal and selected receipt inode in clean replay.
	#[must_use]
	pub fn confirms_live_receipt_ready(
		&self,
		replay: &RemoteWitnessedCloseoutReplay,
		witness: RemoteWitnessIntent,
		receipt: LinuxFileIdentity,
	) -> bool {
		self.kind() == FrameKind::RemoteReceiptReady
			&& clean_live_replay(replay, witness)
			&& replay.phase() == Phase::ReceiptReadyRequiresInspection
			&& replay.boundary() == self.successor()
			&& replay.receipt_ready().is_some_and(|ready| {
				ready.boundary() == self.successor() && ready.receipt() == receipt
			})
	}

	/// Confirms the exact live kind-18 proposal and its original kind 42 in clean replay.
	#[must_use]
	pub fn confirms_live_receipt_commit(
		&self,
		replay: &RemoteWitnessedCloseoutReplay,
		witness: RemoteWitnessIntent,
		ready: RemoteReceiptReady,
	) -> bool {
		self.kind() == FrameKind::ReceiptCommitted
			&& clean_live_replay(replay, witness)
			&& replay.phase() == Phase::ReceiptCommitted
			&& replay.boundary() == self.successor()
			&& ready.boundary() == self.previous()
			&& replay.receipt_ready() == Some(ready)
	}
}

fn check_live_owner(
	replay: &RemoteWitnessedCloseoutReplay,
	trust: &RemoteBootstrapTrust<'_>,
	witness: RemoteWitnessIntent,
) -> Result<(), Error> {
	if !clean_live_replay(replay, witness)
		|| witness.binding().context() != RemoteDownloadContext::for_owner(trust.owner())
	{
		return Err(Error::Binding);
	}
	Ok(())
}

fn clean_live_replay(replay: &RemoteWitnessedCloseoutReplay, witness: RemoteWitnessIntent) -> bool {
	replay.issue().is_none()
		&& replay.witness() == Some(witness)
		&& replay.observed_outcome() == Some(Outcome::Submitted(witness.binding().stage()))
}
