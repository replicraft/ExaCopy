use crate::frame::{ChainHead, Frame, FrameKind};

use super::super::finalization::{
	RemoteDownloadReceipt, RemoteFinalizationBody as Body, RemoteFinalizationRecord,
	RemotePublicationObservation as Observation, RemoteReceiptDigest, RemoteReceiptFrames,
};
use super::super::replay::{
	RemoteDownloadReplay, RemoteReplayIssue, RemoteReplayMismatch as Mismatch,
};
use super::super::retirement::{
	RecordedRetirementObservation, RemoteCaptureRetired, RemoteRetiredCapture, RetirementBinding,
};
use super::super::{
	RemoteDownloadContext, RemoteDownloadError as Error, RemoteDownloadOwnerRecord,
};
use super::{RemoteFinalizationPhase as Phase, RemoteReceiptAssociation as Association};

const DURABILITY_PHASES: usize = 6;

#[derive(Debug)]
pub(in super::super) struct FinalizationHistory {
	expected_qualification: [u8; 32],
	allocation: Option<Frame>,
	prepared: Option<Frame>,
	phases: Vec<Frame>,
	commitment: Option<Frame>,
	committed_digest: Option<RemoteReceiptDigest>,
	phase: Phase,
	retirements: Vec<RemoteRetiredCapture>,
}

impl FinalizationHistory {
	pub(in super::super) fn new(expected_qualification: [u8; 32]) -> Self {
		Self {
			expected_qualification,
			allocation: None,
			prepared: None,
			phases: Vec::with_capacity(DURABILITY_PHASES),
			commitment: None,
			committed_digest: None,
			phase: Phase::Capture,
			retirements: Vec::new(),
		}
	}

	pub(in super::super) const fn phase(&self) -> Phase {
		self.phase
	}

	pub(super) fn seal(&self) -> Option<ChainHead> {
		self.phases.first().map(Frame::head)
	}

	pub(super) const fn committed_digest(&self) -> Option<RemoteReceiptDigest> {
		self.committed_digest
	}

	pub(in super::super) fn retain_capture(&mut self, frame: Frame) {
		match frame.kind() {
			FrameKind::RemoteStageAllocated => {
				self.allocation = Some(frame);
				self.prepared = None;
				self.phases.clear();
				self.phase = Phase::Capture;
			}
			FrameKind::EntryPrepared => self.prepared = Some(frame),
			_ => {}
		}
	}

	pub(super) fn retirements(&self) -> &[RemoteRetiredCapture] {
		&self.retirements
	}

	pub(super) fn retirement_record<'name>(
		&self,
		replay: &RemoteDownloadReplay,
		owner: &RemoteDownloadOwnerRecord,
		observed: RecordedRetirementObservation<'name>,
	) -> Result<RemoteCaptureRetired<'name>, Error> {
		if !matches!(
			self.phase,
			Phase::Sealed | Phase::Verified | Phase::MetadataReady
		) {
			return Err(Error::FrameBinding);
		}
		let bootstrap = replay
			.stage_directory_prepared()
			.ok_or(Error::FrameBinding)?;
		let attempt = replay.attempts().last().ok_or(Error::FrameBinding)?;
		let prepared = attempt.prepared().ok_or(Error::FrameBinding)?;
		let destination = &owner.manifest().scope.destination;
		if observed.directory != prepared.directory
			|| observed.directory != bootstrap.directory()
			|| observed.stage != prepared.file
			|| observed.target.root != destination.root()
			|| observed.target.parent != destination.parent()
			|| observed.target.component.as_bytes() != destination.target()
			|| observed.qualification_digest != self.expected_qualification
		{
			return Err(Error::Binding);
		}
		let binding = RetirementBinding {
			context: RemoteDownloadContext::for_owner(owner),
			scope: owner.manifest().scope.digest()?,
			predecessor: replay.boundary().head,
			bootstrap: bootstrap.head(),
			allocation: attempt.allocation(),
			prepared: prepared.head,
			seal: self.seal().ok_or(Error::FrameBinding)?,
			epochs: attempt.epochs(),
		};
		RemoteCaptureRetired::new(binding, observed)
	}

	pub(in super::super) fn accept_retirement(
		&mut self,
		replay: &RemoteDownloadReplay,
		owner: &RemoteDownloadOwnerRecord,
		frame: &Frame,
	) -> Result<(), Mismatch> {
		if !matches!(
			self.phase,
			Phase::Sealed | Phase::Verified | Phase::MetadataReady
		) {
			return Err(Mismatch::Order);
		}
		let record = RemoteCaptureRetired::from_frame(frame).map_err(Mismatch::Payload)?;
		let expected = self
			.retirement_record(replay, owner, record.observation())
			.map_err(Mismatch::Payload)?;
		if record != expected {
			return Err(Mismatch::StageBinding);
		}

		let binding = record.binding();
		let observed = record.observation();
		self.retirements.push(RemoteRetiredCapture {
			head: frame.head(),
			seal: binding.seal,
			allocation: binding.allocation,
			prepared: binding.prepared,
			directory: observed.directory,
			stage: observed.stage,
			grant_digest: observed.grant_digest,
			qualification_digest: observed.qualification_digest,
		});
		self.phase = Phase::Retired;
		Ok(())
	}

	pub(in super::super) fn accept(
		&mut self,
		replay: &RemoteDownloadReplay,
		owner: &RemoteDownloadOwnerRecord,
		frame: Frame,
	) -> Result<(), Mismatch> {
		if replay.recorded_uncertainty().is_some() {
			return Err(Mismatch::AfterUncertainty);
		}
		let record = RemoteFinalizationRecord::from_frame(&frame).map_err(Mismatch::Payload)?;
		let binding = record.binding();
		if binding.context != RemoteDownloadContext::for_owner(owner) {
			return Err(Mismatch::Context);
		}
		if record.predecessor() != replay.boundary().head {
			return Err(Mismatch::Predecessor);
		}
		let bootstrap = replay
			.stage_directory_prepared()
			.ok_or(Mismatch::BootstrapRequired)?;
		let attempt = replay.attempts().last().ok_or(Mismatch::Order)?;
		let prepared = attempt.prepared().ok_or(Mismatch::Order)?;
		if binding.prepared != prepared.head
			|| binding.epochs != attempt.epochs()
			|| binding.stage != prepared.file
			|| bootstrap.directory() != prepared.directory
		{
			return Err(Mismatch::StageBinding);
		}

		let phase = match (self.phase, record.body()) {
			(Phase::Capture, Body::StageSealed { directory, length }) => {
				if directory != prepared.directory || length != attempt.source().length() {
					return Err(Mismatch::StageBinding);
				}
				Phase::Sealed
			}
			(Phase::Sealed, Body::VerificationRecorded { length, .. }) => {
				if length != attempt.source().length() {
					return Err(Mismatch::StageBinding);
				}
				Phase::Verified
			}
			(Phase::Verified, Body::MetadataRecorded(_)) => Phase::MetadataReady,
			(
				Phase::MetadataReady,
				Body::PublishIntent {
					seal,
					verification,
					directory,
					target,
					qualification,
				},
			) => {
				if self.phases.first().map(Frame::head) != Some(seal)
					|| self.phases.get(1).map(Frame::head) != Some(verification)
					|| directory != prepared.directory
				{
					return Err(Mismatch::StageBinding);
				}
				let destination = &owner.manifest().scope.destination;
				if target.root != destination.root()
					|| target.parent != destination.parent()
					|| target.component.as_bytes() != destination.target()
					|| qualification != self.expected_qualification
				{
					return Err(Mismatch::Scope);
				}
				Phase::Intent
			}
			(Phase::Intent, Body::PublishObserved(observed)) => match observed {
				Observation::Published(_) => Phase::Published,
				Observation::Conflict => Phase::Conflict,
				Observation::Uncertain { .. } => Phase::Uncertain,
			},
			(
				Phase::Published,
				Body::DurabilityRecorded {
					metadata,
					directory,
					parent,
					qualification,
				},
			) => {
				if self.phases.get(2).map(Frame::head) != Some(metadata)
					|| directory != prepared.directory
					|| parent != owner.manifest().scope.destination.parent()
					|| qualification != self.expected_qualification
				{
					return Err(Mismatch::StageBinding);
				}
				self.validate_durability(owner, &frame)
					.map_err(Mismatch::Payload)?;
				Phase::Durable
			}
			(Phase::Durable, Body::ReceiptCommitted { digest }) => {
				let (receipt, frames) = self.reconstruct(owner).map_err(Mismatch::Payload)?;
				receipt
					.validate_evidence(owner, frames, &frame)
					.map_err(Mismatch::Payload)?;
				self.committed_digest = Some(digest);
				Phase::ReceiptCommitted
			}
			_ => return Err(Mismatch::Order),
		};
		if phase == Phase::ReceiptCommitted {
			self.commitment = Some(frame);
		} else {
			self.phases.push(frame);
		}
		self.phase = phase;
		Ok(())
	}

	fn validate_durability(
		&self,
		owner: &RemoteDownloadOwnerRecord,
		durability: &Frame,
	) -> Result<(), Error> {
		let [seal, verification, metadata, intent, observed] = self.phases.as_slice() else {
			return Err(Error::FrameBinding);
		};
		let selected = self.select(seal, verification, metadata, intent, observed, durability)?;
		RemoteDownloadReceipt::from_frames(owner, selected).map(|_| ())
	}

	fn select<'scan>(
		&'scan self,
		seal: &'scan Frame,
		verification: &'scan Frame,
		metadata: &'scan Frame,
		intent: &'scan Frame,
		observed: &'scan Frame,
		durability: &'scan Frame,
	) -> Result<RemoteReceiptFrames<'scan>, Error> {
		Ok(RemoteReceiptFrames {
			allocation: self.allocation.as_ref().ok_or(Error::FrameBinding)?,
			prepared: self.prepared.as_ref().ok_or(Error::FrameBinding)?,
			seal,
			verification,
			metadata,
			intent,
			observed,
			durability,
		})
	}

	fn reconstruct(
		&self,
		owner: &RemoteDownloadOwnerRecord,
	) -> Result<(RemoteDownloadReceipt<'_>, RemoteReceiptFrames<'_>), Error> {
		let [seal, verification, metadata, intent, observed, durability] = self.phases.as_slice()
		else {
			return Err(Error::FrameBinding);
		};
		let frames = self.select(seal, verification, metadata, intent, observed, durability)?;
		Ok((RemoteDownloadReceipt::from_frames(owner, frames)?, frames))
	}

	pub(super) fn receipt(
		&self,
		owner: &RemoteDownloadOwnerRecord,
	) -> Result<Option<RemoteDownloadReceipt<'_>>, Error> {
		if self.phases.len() != DURABILITY_PHASES {
			return Ok(None);
		}
		self.reconstruct(owner).map(|(receipt, _)| Some(receipt))
	}

	pub(super) fn associate(
		&self,
		owner: &RemoteDownloadOwnerRecord,
		issue: Option<&RemoteReplayIssue>,
		receipt: Option<&[u8]>,
	) -> Association {
		let Some(commitment) = &self.commitment else {
			return Association::NotCommitted;
		};
		if issue.is_some() {
			return Association::UnclearEnd;
		}
		let Some(bytes) = receipt else {
			return Association::Missing;
		};
		let result = self.reconstruct(owner).and_then(|(_, frames)| {
			RemoteDownloadReceipt::decode(bytes)?.validate_evidence(owner, frames, commitment)
		});
		match result {
			Ok(()) => Association::Matched,
			Err(error) => Association::Refused(error),
		}
	}
}
