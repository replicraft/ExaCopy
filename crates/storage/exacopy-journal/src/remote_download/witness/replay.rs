//! Explicit historical reader for the selector-2 witnessed closeout grammar.

use std::io::Read;

use crate::frame::ChainHead;
use crate::remote_download::checkpoints::{PrefixOwner, RemotePrefixHistory};
use crate::remote_download::continuation::replay::{
	ContinuedHistory, RemoteWitnessContinuationSelection, validate_witness_selection,
};
use crate::remote_download::finalization_replay::{FinalizationHistory, RemoteFinalizationPhase};
use crate::remote_download::qualification::continuation::VerifiedRemoteWitnessQualification;
use crate::remote_download::replay::{
	RemoteDownloadReplay, RemoteRecordedUncertainty, RemoteReplayAttempt, RemoteReplayBoundary,
	RemoteReplayIssue, scan_witness_closeout,
};
use crate::{LinuxFileIdentity, StreamLength};

use super::records::{RemoteRetainedWitness, RemoteWitnessedOutcome};
use super::{
	Error, RemoteBootstrapTrust, RemoteReceiptReady, RemoteWitnessBinding, RemoteWitnessIntent,
};

mod archive;
mod history;
mod receipt;

pub(in crate::remote_download) use history::WitnessCloseoutHistory;
pub use receipt::{RemoteDurableReceiptBasis, RemoteReceiptReadyInspection};

/// Externally selected historical evidence for the exact witnessed strategy.
#[derive(Debug)]
pub struct RemoteWitnessedReplaySelection<'qualification> {
	/// Independent verified V1 archive for history before the first witnessed pass.
	pub initial_v1_qualification: [u8; 32],
	/// Separate independently verified V1 archive for fresh passes after witnessed retirement.
	pub fresh_v1_qualification: [u8; 32],
	/// Exact separately verified op2 witnessed qualification.
	pub qualification: &'qualification VerifiedRemoteWitnessQualification,
	/// Independently selected archived base-grant digest for all witnessed passes.
	pub grant_digest: [u8; 32],
}

/// Historical phase only. Current native facts and authority require separate admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteWitnessedReplayPhase {
	/// V1 lifecycle, using the initial or independently chosen fresh archive.
	Legacy(RemoteFinalizationPhase),
	/// A fresh post-retirement allocation has no recorded physical binding yet.
	FreshAllocationUnbound,
	/// Active continued data pass before signed witness intent.
	ContinuedCapture,
	/// Signed witness intent exists. Inspect the protected names before any restart decision.
	WitnessIntentRequiresInspection,
	/// Witness and stage seal evidence were recorded.
	Sealed,
	/// Independent whole-stream digest comparison was recorded.
	Verified,
	/// Exact SFTP selected-stream metadata policy evidence was recorded.
	MetadataReady,
	/// Publication was intended. The restart may observe only this prior attempt.
	PublishIntentRequiresObservation,
	/// A positive live or recovered publication was recorded before durability.
	PublishedObserved,
	/// Full file and all selected directory barrier declarations were accepted.
	Durable,
	/// Receipt-ready evidence exists. Independently inspect pending and final names.
	ReceiptReadyRequiresInspection,
	/// Receipt commitment is recorded. The final artifact has not been inspected by this scan.
	ReceiptCommitted,
	/// Pre-intent retirement was recorded, awaiting independently admitted fresh allocation.
	Retired,
	/// Definite conflict was recorded. No further effect is implied.
	Conflict,
	/// An uncertain outcome or failure was recorded as terminal diagnostics.
	Uncertain,
}

/// Retired historical stage and exact recorded protected witness preservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteWitnessedRetirement {
	/// Exact accepted retirement head.
	pub head: ChainHead,
	/// Original physical allocation and retired active run scope.
	pub binding: RemoteWitnessBinding,
	/// Recorded state of the protected alias.
	pub witness: RemoteRetainedWitness,
}

/// Read-only result for a bounded selected first segment.
///
/// No result grants write, prefix reuse, current consent, or namespace authority.
pub struct RemoteWitnessedCloseoutReplay {
	prefix: RemoteDownloadReplay,
	history: history::CloseoutFacts,
	continued: ContinuedHistory,
	prefix_owner: PrefixOwner,
	qualification: [u8; 32],
	grant: [u8; 32],
	fallback: RemoteFinalizationPhase,
	pass_count: usize,
}

impl RemoteWitnessedCloseoutReplay {
	/// Returns the latest semantically accepted head and offset, even on refusal.
	#[must_use]
	pub const fn boundary(&self) -> RemoteReplayBoundary {
		self.prefix.boundary()
	}

	/// Returns the authenticated logical history's current phase.
	#[must_use]
	pub fn phase(&self) -> RemoteWitnessedReplayPhase {
		let phase = self.history.phase(self.fallback);
		if phase == RemoteWitnessedReplayPhase::Legacy(RemoteFinalizationPhase::Capture)
			&& !self.history.retirements.is_empty()
			&& self
				.attempts()
				.last()
				.is_some_and(|attempt| attempt.prepared().is_none())
		{
			return RemoteWitnessedReplayPhase::FreshAllocationUnbound;
		}
		phase
	}

	/// Returns any framing, ordering or recorded uncertainty needing reconciliation.
	#[must_use]
	pub const fn issue(&self) -> Option<&RemoteReplayIssue> {
		self.prefix.issue()
	}

	/// Returns the physical allocation history, including unresolved names.
	#[must_use]
	pub fn attempts(&self) -> &[RemoteReplayAttempt] {
		self.prefix.attempts()
	}

	/// Returns the consumed job-wide count including both fresh and continued passes.
	#[must_use]
	pub const fn pass_count(&self) -> usize {
		self.pass_count
	}

	/// Returns witnessed retirements in order, preserving implicit historical aliases.
	#[must_use]
	pub fn retirements(&self) -> &[RemoteWitnessedRetirement] {
		&self.history.retirements
	}

	/// Returns the recorded signed witness fence of the active pass, if any.
	#[must_use]
	pub const fn witness(&self) -> Option<RemoteWitnessIntent> {
		self.history.witness
	}

	/// Returns the submitted, recovered, conflict, or uncertain facts as recorded.
	#[must_use]
	pub const fn observed_outcome(&self) -> Option<RemoteWitnessedOutcome> {
		self.history.outcome
	}

	/// Returns historical failure evidence for the exact last failed operation.
	#[must_use]
	pub fn recorded_failure(&self) -> Option<RemoteRecordedUncertainty> {
		self.history
			.failure
			.or_else(|| self.prefix.recorded_uncertainty())
	}

	/// Returns the accepted canonical pending receipt declaration, if present.
	#[must_use]
	pub const fn receipt_ready(&self) -> Option<RemoteReceiptReady> {
		self.history.ready
	}

	/// Compares exact bytes to the historical receipt under its accepted committed inode.
	///
	/// Current file custody and location require a separately held native inspection.
	#[must_use]
	pub fn matches_committed_receipt(&self, inode: LinuxFileIdentity, bytes: &[u8]) -> bool {
		self.issue().is_none()
			&& self.history.phase(self.fallback) == RemoteWitnessedReplayPhase::ReceiptCommitted
			&& self
				.history
				.ready
				.is_some_and(|ready| ready.receipt() == inode)
			&& self.history.receipt.as_ref().map(receipt::Artifact::bytes) == Some(bytes)
	}

	/// Borrows all historical bytes declared covered in the active clean continued pass.
	///
	/// The caller must independently reread and verify all reused bytes.
	/// # Errors
	/// Refuses witness intent, retirement, uncertain or incomplete framing, or no continued pass.
	pub fn active_prefix_history(&self) -> Result<RemotePrefixHistory<'_>, Error> {
		if self.issue().is_some() || self.phase() != RemoteWitnessedReplayPhase::ContinuedCapture {
			return Err(Error::Binding);
		}
		RemotePrefixHistory::continued(
			self.prefix_owner,
			self.attempts().last().ok_or(Error::Binding)?,
			self.boundary(),
			self.qualification,
			self.grant,
			self.continued.active().ok_or(Error::Binding)?,
		)
	}

	/// Returns the complete or partial extent recorded on the active continued pass.
	#[must_use]
	pub const fn continued_extent(&self) -> Option<StreamLength> {
		self.history.continued_extent
	}
}

/// Scans one explicitly selected witnessed closeout history.
///
/// No authority is inferred from archive-selected digests, current wall clock,
/// a recorded outcome or a caller-provided byte stream.
/// # Errors
/// Refuses invalid independent selections before scanning.
pub fn replay_remote_witnessed_closeout(
	input: impl Read,
	trust: &RemoteBootstrapTrust<'_>,
	selection: &RemoteWitnessedReplaySelection<'_>,
) -> Result<RemoteWitnessedCloseoutReplay, Error> {
	let witness_selection = RemoteWitnessContinuationSelection {
		initial_v1_qualification: selection.initial_v1_qualification,
		qualification: selection.qualification,
		grant_digest: selection.grant_digest,
	};
	validate_witness_selection(trust, &witness_selection)?;
	if selection.fresh_v1_qualification == [0; 32]
		|| &selection.fresh_v1_qualification == selection.qualification.digest().as_bytes()
	{
		return Err(Error::Binding);
	}
	let prefix_owner = PrefixOwner::from_owner(trust.owner())?;
	let mut legacy = FinalizationHistory::new(selection.initial_v1_qualification);
	let mut continued = ContinuedHistory::new(
		selection.initial_v1_qualification,
		*selection.qualification.digest().as_bytes(),
		selection.grant_digest,
		true,
	);
	let mut mixed = WitnessCloseoutHistory::new(selection);
	let prefix = scan_witness_closeout(input, trust, &mut legacy, &mut continued, &mut mixed)?;
	let pass_count = mixed.pass_count(prefix.attempts().len());
	Ok(RemoteWitnessedCloseoutReplay {
		prefix,
		history: mixed.into_facts(),
		continued,
		prefix_owner,
		qualification: *selection.qualification.digest().as_bytes(),
		grant: selection.grant_digest,
		fallback: legacy.phase(),
		pass_count,
	})
}
