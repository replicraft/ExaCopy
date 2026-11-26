use crate::LinuxFileIdentity;
use crate::frame::{Frame, FrameKind};
use crate::remote_download::replay::{RemoteReplayAttempt, RemoteReplayBoundary};

use super::super::super::receipt_ready::{FINAL_NAME_BYTES, PENDING_NAME_BYTES, names};
use super::super::super::{
	Error, ReceiptReadyExpectation, RemoteReceiptReady, RemoteWitnessIntent,
};
use super::super::{RemoteWitnessedCloseoutReplay, RemoteWitnessedReplayPhase as Phase};
use super::{Artifact, Cut, check_receipt_inode};

impl RemoteWitnessedCloseoutReplay {
	/// Derives the canonical receipt and exact historical anchors at a clean kind 9.
	///
	/// A basis carries no current native evidence, live authorization, or receipt inode.
	/// # Errors
	/// Refuses any other phase, unclean tail, or incomplete canonical receipt evidence.
	pub fn durable_receipt_basis(&self) -> Result<RemoteDurableReceiptBasis<'_>, Error> {
		if self.issue().is_some() || self.phase() != Phase::Durable {
			return Err(Error::Binding);
		}
		let cut = self.history.receipt_cut.ok_or(Error::FrameBinding)?;
		let frames = &self.history.durable_frames;
		let durability = frames.last().ok_or(Error::FrameBinding)?;
		if cut.durable != self.boundary()
			|| durability.kind() != FrameKind::DurabilityRecorded
			|| durability.head() != cut.durable.head
		{
			return Err(Error::FrameBinding);
		}
		let witness = self.witness().ok_or(Error::FrameBinding)?;
		let (pending, final_name) = names(witness);
		Ok(RemoteDurableReceiptBasis {
			artifact: Artifact::from_frames(witness, frames)?,
			witness,
			cut,
			durability,
			attempts: self.attempts(),
			pending,
			final_name,
		})
	}

	/// Borrows the exact historical receipt declaration at a clean kind 42.
	///
	/// Inspect both names and the exact bytes independently under current authority.
	/// # Errors
	/// Refuses any other phase, unclean tail, or incomplete canonical receipt evidence.
	pub fn receipt_ready_inspection(&self) -> Result<RemoteReceiptReadyInspection<'_>, Error> {
		if self.issue().is_some() || self.phase() != Phase::ReceiptReadyRequiresInspection {
			return Err(Error::Binding);
		}
		let record = self.receipt_ready().ok_or(Error::FrameBinding)?;
		let cut = self.history.receipt_cut.ok_or(Error::FrameBinding)?;
		let artifact = self.history.receipt.as_ref().ok_or(Error::FrameBinding)?;
		if record.boundary() != self.boundary() {
			return Err(Error::FrameBinding);
		}
		let witness = self.witness().ok_or(Error::FrameBinding)?;
		let (pending, final_name) = names(witness);
		Ok(RemoteReceiptReadyInspection {
			artifact,
			witness,
			durable: cut.durable,
			record,
			pending,
			final_name,
		})
	}
}

/// Bounded receipt bytes reconstructed from the authoritative seven accepted frames.
#[derive(Debug)]
#[must_use]
pub struct RemoteDurableReceiptBasis<'history> {
	artifact: Artifact,
	witness: RemoteWitnessIntent,
	cut: Cut,
	durability: &'history Frame,
	attempts: &'history [RemoteReplayAttempt],
	pending: [u8; PENDING_NAME_BYTES],
	final_name: [u8; FINAL_NAME_BYTES],
}

impl RemoteDurableReceiptBasis<'_> {
	/// Borrows the complete canonical receipt artifact.
	#[must_use]
	pub fn bytes(&self) -> &[u8] {
		self.artifact.bytes()
	}

	/// Returns the bounded canonical byte length.
	#[must_use]
	pub const fn length(&self) -> u16 {
		self.artifact.length
	}

	/// Returns the domain-bound canonical artifact digest.
	#[must_use]
	pub const fn digest(&self) -> [u8; 32] {
		self.artifact.digest
	}

	/// Returns the exact accepted historical kind-9 boundary.
	#[must_use]
	pub const fn boundary(&self) -> RemoteReplayBoundary {
		self.cut.durable
	}

	/// Returns the authenticated historical kind-41 witness.
	#[must_use]
	pub const fn witness(&self) -> RemoteWitnessIntent {
		self.witness
	}

	/// Returns the protected job root identity recorded by the witness.
	#[must_use]
	pub const fn job_directory(&self) -> LinuxFileIdentity {
		self.witness.job_directory()
	}

	/// Returns the destination parent identity recorded by the witness.
	#[must_use]
	pub const fn target_parent(&self) -> LinuxFileIdentity {
		self.witness.target_parent
	}

	/// Borrows the exact derived pending basename.
	#[must_use]
	pub fn pending_name(&self) -> &[u8] {
		&self.pending
	}

	/// Borrows the exact derived final basename.
	#[must_use]
	pub fn final_name(&self) -> &[u8] {
		&self.final_name
	}

	/// Assembles structural kind-42 expectations around an independently resolved inode.
	///
	/// The caller establishes held identity, exact bytes, protection, successful barriers,
	/// and live authorization before using these expectations to encode or submit a record.
	/// # Errors
	/// Refuses a receipt inode already bound to any prepared stage in the selected history.
	pub fn receipt_ready_expectation(
		&self,
		receipt: LinuxFileIdentity,
	) -> Result<ReceiptReadyExpectation<'_>, Error> {
		check_receipt_inode(self.attempts, receipt)?;
		Ok(self
			.artifact
			.expectation(self.witness, self.cut, self.durability, receipt))
	}
}

/// Historical kind-42 declaration and canonical bytes to compare during inspection.
#[derive(Debug)]
#[must_use]
pub struct RemoteReceiptReadyInspection<'history> {
	artifact: &'history Artifact,
	witness: RemoteWitnessIntent,
	durable: RemoteReplayBoundary,
	record: RemoteReceiptReady,
	pending: [u8; PENDING_NAME_BYTES],
	final_name: [u8; FINAL_NAME_BYTES],
}

impl RemoteReceiptReadyInspection<'_> {
	/// Borrows the complete canonical receipt artifact.
	#[must_use]
	pub fn bytes(&self) -> &[u8] {
		self.artifact.bytes()
	}

	/// Returns the exact accepted historical kind-42 boundary.
	#[must_use]
	pub const fn boundary(&self) -> RemoteReplayBoundary {
		self.record.boundary()
	}

	/// Returns the exact historical kind-9 ancestor.
	#[must_use]
	pub const fn durability_boundary(&self) -> RemoteReplayBoundary {
		self.durable
	}

	/// Returns the accepted kind-42 declaration, including its historical receipt inode.
	#[must_use]
	pub const fn record(&self) -> RemoteReceiptReady {
		self.record
	}

	/// Returns the authenticated historical kind-41 witness.
	#[must_use]
	pub const fn witness(&self) -> RemoteWitnessIntent {
		self.witness
	}

	/// Returns the protected job root identity recorded by the witness.
	#[must_use]
	pub const fn job_directory(&self) -> LinuxFileIdentity {
		self.witness.job_directory()
	}

	/// Returns the destination parent identity recorded by the witness.
	#[must_use]
	pub const fn target_parent(&self) -> LinuxFileIdentity {
		self.witness.target_parent
	}

	/// Borrows the exact historically declared pending basename.
	#[must_use]
	pub fn pending_name(&self) -> &[u8] {
		&self.pending
	}

	/// Borrows the exact historically declared final basename.
	#[must_use]
	pub fn final_name(&self) -> &[u8] {
		&self.final_name
	}
}
