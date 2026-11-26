//! Read-only inspection of the bounded, bootstrap-authenticated finalization profile.

use std::io::Read;

use crate::frame::ChainHead;

use super::finalization::{RemoteDownloadReceipt, RemoteReceiptDigest};
use super::finalization_policy::SftpDataOnlyV1;
use super::replay::{
	self, RemoteDownloadReplay, RemoteReplayAttempt, RemoteReplayBoundary, RemoteReplayIssue,
};
use super::{
	RemoteBootstrapTrust, RemoteDownloadError, RemoteDownloadOwnerRecord,
	RemoteStageDirectoryPrepared,
};

use super::retirement::{
	RemoteRetiredCapture, RemoteRetirementCandidate, RemoteRetirementObservation,
};

mod history;

pub(super) use history::FinalizationHistory;

/// Last accepted finalization phase. Physical effects must be checked independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteFinalizationPhase {
	/// No finalization declaration was accepted.
	Capture,
	/// The writer and capture are closed. Recovery must preserve the sealed stage.
	Sealed,
	/// The selected stream read-back and live source digest agree.
	Verified,
	/// Local metadata readiness was recorded.
	MetadataReady,
	/// The old sealed capture was retired and remains preserved. A fresh allocation may follow.
	Retired,
	/// Exclusive publication was intended. A missing observation requires reconciliation.
	Intent,
	/// The exact stage identity was recorded at the target.
	Published,
	/// The no-replace operation recorded a conflict and no receipt is admissible.
	Conflict,
	/// The recorded effect requires reconciliation.
	Uncertain,
	/// Publication barriers were declared and a receipt commitment may be missing.
	Durable,
	/// A terminal frame commits the exact canonical receipt digest.
	ReceiptCommitted,
}

/// Association of a separately selected receipt artifact with the accepted journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RemoteReceiptAssociation {
	/// There is no accepted terminal commitment.
	NotCommitted,
	/// The commitment is present and the artifact was not supplied.
	Missing,
	/// The supplied artifact differs from the committed canonical evidence.
	Refused(RemoteDownloadError),
	/// An unreadable, torn or unsupported suffix prevents association.
	UnclearEnd,
	/// The exact artifact matched the commitment at clear EOF.
	Matched,
}

/// Historical observations from one bounded scan. The caller selects the held input.
#[derive(Debug)]
pub struct RemoteFinalizationReplay<'owner> {
	owner: &'owner RemoteDownloadOwnerRecord,
	prefix: RemoteDownloadReplay,
	history: FinalizationHistory,
	association: RemoteReceiptAssociation,
}

impl RemoteFinalizationReplay<'_> {
	/// Returns the exact end of the last accepted frame.
	#[must_use]
	pub const fn boundary(&self) -> RemoteReplayBoundary {
		self.prefix.boundary()
	}

	/// Returns the accepted historical bootstrap declaration, if present.
	#[must_use]
	pub const fn stage_directory_prepared(&self) -> Option<RemoteStageDirectoryPrepared> {
		self.prefix.stage_directory_prepared()
	}

	/// Returns all accepted historical allocations, including superseded ones.
	#[must_use]
	pub fn attempts(&self) -> &[RemoteReplayAttempt] {
		self.prefix.attempts()
	}

	/// Returns the expected qualification digest supplied for this historical scan.
	#[must_use]
	pub const fn expected_qualification(&self) -> [u8; 32] {
		self.history.expected_qualification()
	}

	/// Returns the last accepted finalization phase, even when a suffix was refused.
	#[must_use]
	pub const fn phase(&self) -> RemoteFinalizationPhase {
		self.history.phase()
	}

	/// Returns the first refused condition without advancing the accepted boundary.
	#[must_use]
	pub const fn issue(&self) -> Option<&RemoteReplayIssue> {
		self.prefix.issue()
	}

	/// Returns the accepted retirement records while preserving their old stage inventory.
	#[must_use]
	pub fn retirements(&self) -> &[RemoteRetiredCapture] {
		self.history.retirements()
	}

	/// Matches a retirement declaration to the selected clear pre-intent history.
	///
	/// Supply the independently authorized current grant and physical observations
	/// under the same exclusive lease. Recheck current authority and writer head
	/// before the journal append. This method performs no native observation.
	///
	/// # Errors
	/// Refuses an unclean history, a sent intent, a mismatched grant, stage name or native identity,
	/// or any prefix other than a sealed, verified, or metadata-ready capture.
	pub fn retirement_candidate<'name>(
		&self,
		approved_grant_digest: [u8; 32],
		observed: RemoteRetirementObservation<'name>,
	) -> Result<RemoteRetirementCandidate<'name>, RemoteDownloadError> {
		if self.issue().is_some() || approved_grant_digest != observed.grant_digest {
			return Err(RemoteDownloadError::Binding);
		}
		let attempt = self
			.prefix
			.attempts()
			.last()
			.ok_or(RemoteDownloadError::FrameBinding)?;
		if observed.stage_name.as_bytes() != attempt.name() {
			return Err(RemoteDownloadError::Binding);
		}
		let record =
			self.history
				.retirement_record(&self.prefix, self.owner, observed.recorded()?)?;
		Ok(RemoteRetirementCandidate::new(record))
	}

	/// Returns the accepted seal boundary, when present.
	#[must_use]
	pub fn seal(&self) -> Option<ChainHead> {
		self.history.seal()
	}

	/// Returns the historical terminal commitment, even when its artifact is absent.
	#[must_use]
	pub const fn committed_digest(&self) -> Option<RemoteReceiptDigest> {
		self.history.committed_digest()
	}

	/// Returns the supplied artifact's association status.
	#[must_use]
	pub const fn receipt_association(&self) -> RemoteReceiptAssociation {
		self.association
	}

	/// Reconstructs canonical candidate bytes from the checked durability history.
	///
	/// # Errors
	/// Fails if the retained declarations cannot be represented as a canonical receipt.
	pub fn receipt_candidate(
		&self,
	) -> Result<Option<RemoteDownloadReceipt<'_>>, RemoteDownloadError> {
		if self.issue().is_some() {
			return Ok(None);
		}
		self.history.receipt(self.owner)
	}

	/// Returns the associated receipt only after an exact commitment and clear EOF.
	///
	/// # Errors
	/// Fails if the retained declarations cannot be represented as a canonical receipt.
	pub fn validated_receipt(
		&self,
	) -> Result<Option<RemoteDownloadReceipt<'_>>, RemoteDownloadError> {
		if self.association != RemoteReceiptAssociation::Matched {
			return Ok(None);
		}
		self.receipt_candidate()
	}
}

/// Checks one exact bounded selected first segment under an authenticated bootstrap.
///
/// Supply the independently expected qualification digest and optional exact bytes
/// from the selected receipt object. These inputs and the returned history convey
/// no authority over current objects, writers or native effects.
///
/// # Errors
/// Refuses a different or unknown signed policy or a missing qualification digest.
/// Framing and semantic failures retain the accepted boundary in the returned scan.
pub fn replay_remote_finalization<'owner>(
	input: impl Read,
	trust: &RemoteBootstrapTrust<'owner>,
	expected_qualification: [u8; 32],
	receipt: Option<&[u8]>,
) -> Result<RemoteFinalizationReplay<'owner>, RemoteDownloadError> {
	let owner = trust.owner();
	if owner.manifest().scope.metadata_policy != SftpDataOnlyV1::digest()
		|| expected_qualification == [0; 32]
	{
		return Err(RemoteDownloadError::Binding);
	}
	let mut history = FinalizationHistory::new(expected_qualification);
	let prefix = replay::scan_finalization(input, trust, &mut history)?;
	let association = history.associate(owner, prefix.issue(), receipt);
	Ok(RemoteFinalizationReplay {
		owner,
		prefix,
		history,
		association,
	})
}
