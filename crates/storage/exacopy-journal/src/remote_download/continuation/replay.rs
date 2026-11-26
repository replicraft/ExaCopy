//! Read-only historical admission of the first continued capture profile.

use std::io::Read;

use crate::frame::{ChainHead, Frame};
use crate::{StreamDigest, StreamLength};

use super::{Error, RemoteBootstrapTrust, RemoteEpochs, RemoteSourceObservation};
use crate::remote_download::checkpoints::{
	PrefixOwner, RemotePrefixHistory, RemoteVerifiedCheckpoint,
};
use crate::remote_download::finalization_policy::SftpDataOnlyV1;
use crate::remote_download::finalization_replay::{FinalizationHistory, RemoteFinalizationPhase};
use crate::remote_download::qualification::{
	RemoteQualificationRouteClass, continuation::VerifiedRemoteContinuationQualification,
};
use crate::remote_download::replay::{
	RemoteDownloadReplay, RemoteRecordedUncertainty, RemoteReplayAttempt, RemoteReplayBoundary,
	RemoteReplayIssue, scan_continuation,
};
use crate::remote_download::{RemoteDownloadRoute, RemoteStageDirectoryPrepared};

mod history;

pub(in super::super) use history::ContinuedHistory;

/// Independently selected trust for one archived remote job.
#[derive(Debug)]
pub struct RemoteContinuationSelection<'qualification> {
	/// Expected old qualification digest for any V1 retirement and finalization records.
	pub legacy_qualification: [u8; 32],
	/// Separate verified strategy qualification for kind-40 records.
	pub qualification: &'qualification VerifiedRemoteContinuationQualification,
	/// Exact approved immutable grant digest for the owner's signed scope.
	pub grant_digest: [u8; 32],
}

/// Accepted historical information for the one active continued pass.
#[derive(Debug)]
pub struct RemoteContinuedCapture {
	frame: Frame,
	admitted_at: RemoteReplayBoundary,
	epochs: RemoteEpochs,
	source: RemoteSourceObservation,
	adopted_end: StreamLength,
	prefix_digest: StreamDigest,
	checkpoints: Vec<RemoteVerifiedCheckpoint>,
	covered_end: u64,
}

impl RemoteContinuedCapture {
	/// Returns the exact signed frame admitted as the new active preparation.
	#[must_use]
	pub const fn frame(&self) -> &Frame {
		&self.frame
	}

	/// Returns the immutable admitted lineage head and offset.
	#[must_use]
	pub const fn admitted_at(&self) -> RemoteReplayBoundary {
		self.admitted_at
	}

	/// Returns the historical continued run and source labels.
	#[must_use]
	pub const fn epochs(&self) -> RemoteEpochs {
		self.epochs
	}

	/// Returns the fresh SFTP observation recorded at the continuation boundary.
	#[must_use]
	pub const fn source(&self) -> RemoteSourceObservation {
		self.source
	}

	/// Returns the exclusive end and digest of the adopted prefix from zero.
	#[must_use]
	pub const fn adopted_prefix(&self) -> (StreamLength, StreamDigest) {
		(self.adopted_end, self.prefix_digest)
	}

	/// Returns only suffix declarations. Their coverage starts after the adopted prefix.
	#[must_use]
	pub fn checkpoints(&self) -> &[RemoteVerifiedCheckpoint] {
		&self.checkpoints
	}

	/// Returns the exclusive end of the aggregate plus contiguous suffix checkpoints.
	#[must_use]
	pub const fn covered_end(&self) -> u64 {
		self.covered_end
	}
}

/// Read-only classification of one checked first segment.
#[derive(Debug)]
#[non_exhaustive]
pub enum RemoteContinuationState<'scan> {
	/// No continuation was accepted. Report the exact selected legacy phase.
	Legacy(RemoteFinalizationPhase),
	/// The one historical continued pass reached a clean EOF.
	Continued(&'scan RemoteContinuedCapture),
	/// The current input did not end at a clean admissible capture boundary.
	ReconciliationRequired(&'scan RemoteReplayIssue),
}

/// History from the explicit continuation-aware scanner.
///
/// No writer, current source, barrier, native qualification or publication
/// authority can be recovered from these recorded declarations.
pub struct RemoteContinuationReplay {
	prefix: RemoteDownloadReplay,
	phase: RemoteFinalizationPhase,
	continued: ContinuedHistory,
	prefix_owner: PrefixOwner,
	qualification: [u8; 32],
	grant: [u8; 32],
}

impl RemoteContinuationReplay {
	/// Returns the exact last semantically accepted frame boundary.
	#[must_use]
	pub const fn boundary(&self) -> RemoteReplayBoundary {
		self.prefix.boundary()
	}

	/// Returns the original allocations with their original epochs and provenance.
	#[must_use]
	pub fn attempts(&self) -> &[RemoteReplayAttempt] {
		self.prefix.attempts()
	}

	/// Returns the accepted original job preparation, if any.
	#[must_use]
	pub const fn job_prepared(&self) -> Option<ChainHead> {
		self.prefix.job_prepared()
	}

	/// Returns the accepted signed historical stage-directory observation.
	#[must_use]
	pub const fn stage_directory_prepared(&self) -> Option<RemoteStageDirectoryPrepared> {
		self.prefix.stage_directory_prepared()
	}

	/// Returns a recorded failure even when a later suffix was also refused.
	#[must_use]
	pub fn recorded_uncertainty(&self) -> Option<RemoteRecordedUncertainty> {
		self.continued
			.failure()
			.or_else(|| self.prefix.recorded_uncertainty())
	}

	/// Returns the complete coverage of a clean active continued capture.
	///
	/// # Errors
	/// Refuses legacy, uncertain, torn or semantically rejected history.
	pub fn active_prefix_history(&self) -> Result<RemotePrefixHistory<'_>, Error> {
		let RemoteContinuationState::Continued(active) = self.state() else {
			return Err(Error::Binding);
		};
		if self.recorded_uncertainty().is_some() || self.phase != RemoteFinalizationPhase::Capture {
			return Err(Error::Binding);
		}
		RemotePrefixHistory::continued(
			self.prefix_owner,
			self.attempts().last().ok_or(Error::Binding)?,
			self.boundary(),
			self.qualification,
			self.grant,
			active,
		)
	}

	/// Returns the historical classification and preserves any reconciliation reason.
	#[must_use]
	pub const fn state(&self) -> RemoteContinuationState<'_> {
		if let Some(issue) = self.prefix.issue() {
			RemoteContinuationState::ReconciliationRequired(issue)
		} else if let Some(continued) = self.continued.active() {
			RemoteContinuationState::Continued(continued)
		} else {
			RemoteContinuationState::Legacy(self.phase)
		}
	}
}

/// Inspects a bounded selected first segment with explicit continuation admission.
///
/// A fresh original preparation and positive historical V1 checkpoint can lead
/// to one signed kind-40 declaration, followed by versioned suffix checkpoints
/// or an exact recorded failure. Subsequent allocation, finalization and
/// retirement grammars for continued stages remain separately selected work.
/// The selected grant digest is historical scope information. The verifier
/// result carries attested facts and no current native approval.
///
/// # Errors
/// Refuses inconsistent selection before reading. Framing, semantic failures
/// and uncertainty in the input are retained at the exact accepted boundary.
pub fn replay_remote_continuation(
	input: impl Read,
	trust: &RemoteBootstrapTrust<'_>,
	selection: &RemoteContinuationSelection<'_>,
) -> Result<RemoteContinuationReplay, Error> {
	validate_selection(trust, selection)?;
	let prefix_owner = PrefixOwner::from_owner(trust.owner())?;
	let qualification = *selection.qualification.digest().as_bytes();
	let mut legacy = FinalizationHistory::new(selection.legacy_qualification);
	let mut continued = ContinuedHistory::new(
		selection.legacy_qualification,
		qualification,
		selection.grant_digest,
	);
	let prefix = scan_continuation(input, trust, &mut legacy, &mut continued)?;
	Ok(RemoteContinuationReplay {
		prefix,
		phase: legacy.phase(),
		continued,
		prefix_owner,
		qualification,
		grant: selection.grant_digest,
	})
}

fn validate_selection(
	trust: &RemoteBootstrapTrust<'_>,
	selection: &RemoteContinuationSelection<'_>,
) -> Result<(), Error> {
	let owner_scope = &trust.owner().manifest().scope;
	let parent = owner_scope.destination.parent();
	let observed_parent = selection.qualification.facts().ids().root;
	let route = match owner_scope.source.route() {
		RemoteDownloadRoute::ResolvedDirect { .. } => {
			RemoteQualificationRouteClass::DirectPinnedTcpV1
		}
		RemoteDownloadRoute::EmbeddedWireGuard { .. } => {
			RemoteQualificationRouteClass::EmbeddedWireGuardTcpV1
		}
		_ => return Err(Error::Scope),
	};
	if owner_scope.metadata_policy != SftpDataOnlyV1::digest()
		|| selection.grant_digest == [0; 32]
		|| selection.legacy_qualification == [0; 32]
		|| selection.legacy_qualification == *selection.qualification.digest().as_bytes()
		|| !selection.qualification.matches_owner(trust.key())
		|| selection.qualification.scope().common.route != route
		|| observed_parent.device != parent.device()
		|| observed_parent.inode != parent.inode()
	{
		return Err(Error::Binding);
	}
	Ok(())
}
