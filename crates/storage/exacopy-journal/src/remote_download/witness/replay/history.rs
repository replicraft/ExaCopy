use crate::frame::{ChainHead, Frame, FrameKind};
use crate::remote_download::RemoteDownloadDestination;
use crate::remote_download::continuation::replay::RemoteContinuedCapture;
use crate::remote_download::finalization::RemoteLocalMetadata;
use crate::remote_download::finalization_replay::RemoteFinalizationPhase;
use crate::remote_download::qualification::continuation::VerifiedRemoteWitnessQualification;
use crate::remote_download::replay::{
	RemoteDownloadReplay, RemoteRecordedUncertainty, RemoteReplayBoundary, RemoteReplayMismatch,
};
use crate::{StreamDigest, StreamLength};

use super::super::records::{
	RemoteRetainedWitness, RemoteWitnessCloseoutBody as Body,
	RemoteWitnessCloseoutRecord as Record, RemoteWitnessedOutcome as Outcome,
};
use super::super::{
	Error, MAX_REMOTE_RECEIPT_READY_BYTES, MAX_REMOTE_WITNESS_INTENT_BYTES, RemoteBootstrapTrust,
	RemoteReceiptReady, RemoteWitnessBinding, RemoteWitnessIntent, binding_for,
};
use super::{
	RemoteWitnessedReplayPhase as Phase, RemoteWitnessedReplaySelection, RemoteWitnessedRetirement,
	archive, receipt,
};

mod validation;

#[derive(Default)]
pub(super) struct CloseoutFacts {
	phase: Option<Phase>,
	pub(super) witness: Option<RemoteWitnessIntent>,
	pub(super) retirements: Vec<RemoteWitnessedRetirement>,
	pub(super) outcome: Option<Outcome>,
	pub(super) failure: Option<RemoteRecordedUncertainty>,
	pub(super) ready: Option<RemoteReceiptReady>,
	pub(super) receipt: Option<receipt::Artifact>,
	pub(super) receipt_cut: Option<receipt::Cut>,
	pub(super) durable_frames: Vec<Frame>,
	pub(super) prepublication_heads: Option<(ChainHead, ChainHead)>,
	pub(super) durability_metadata_head: Option<ChainHead>,
	pub(super) continued_extent: Option<StreamLength>,
	pub(super) verified_stage_digest: Option<StreamDigest>,
	pub(super) metadata: Option<RemoteLocalMetadata>,
	pub(super) committed_destination: Option<RemoteDownloadDestination>,
}

impl CloseoutFacts {
	pub(super) const fn phase(&self, fallback: RemoteFinalizationPhase) -> Phase {
		match self.phase {
			Some(value) => value,
			None => Phase::Legacy(fallback),
		}
	}
}

pub(in crate::remote_download) struct WitnessCloseoutHistory<'qualification> {
	qualification: &'qualification VerifiedRemoteWitnessQualification,
	grant: [u8; 32],
	fresh_qualification: [u8; 32],
	continued_passes: usize,
	facts: CloseoutFacts,
	phases: Vec<Frame>,
	observed: Option<RemoteReplayBoundary>,
}

impl<'qualification> WitnessCloseoutHistory<'qualification> {
	pub(super) fn new(selection: &RemoteWitnessedReplaySelection<'qualification>) -> Self {
		Self {
			qualification: selection.qualification,
			grant: selection.grant_digest,
			fresh_qualification: selection.fresh_v1_qualification,
			continued_passes: 0,
			facts: CloseoutFacts::default(),
			phases: Vec::with_capacity(7),
			observed: None,
		}
	}

	pub(super) fn into_facts(mut self) -> CloseoutFacts {
		match self.facts.phase {
			Some(Phase::MetadataReady) => {
				self.facts.prepublication_heads = self
					.head(FrameKind::StageSealed)
					.ok()
					.zip(self.head(FrameKind::VerificationRecorded).ok());
			}
			Some(Phase::PublishedObserved) => {
				self.facts.durability_metadata_head = self.head(FrameKind::MetadataRecorded).ok();
			}
			Some(Phase::Durable) => self.facts.durable_frames = self.phases,
			_ => {}
		}
		self.facts
	}

	pub(in crate::remote_download) const fn pass_count(&self, physical: usize) -> usize {
		physical + self.continued_passes
	}

	pub(in crate::remote_download) const fn retired(&self) -> bool {
		matches!(self.facts.phase, Some(Phase::Retired))
	}

	pub(in crate::remote_download) const fn before_witness(&self) -> bool {
		matches!(self.facts.phase, Some(Phase::ContinuedCapture))
	}

	pub(in crate::remote_download) const fn uncertain(&self) -> bool {
		matches!(self.facts.phase, Some(Phase::Uncertain))
	}

	pub(in crate::remote_download) const fn is_initial_legacy(&self) -> bool {
		self.facts.phase.is_none() && self.facts.retirements.is_empty()
	}

	pub(in crate::remote_download) fn in_fresh_legacy(&self) -> bool {
		self.facts.phase.is_none() && !self.facts.retirements.is_empty()
	}

	pub(in crate::remote_download) const fn fresh_qualification(&self) -> [u8; 32] {
		self.fresh_qualification
	}

	pub(in crate::remote_download) fn note_fresh(&mut self) {
		self.facts.phase = None;
		self.facts.witness = None;
		self.facts.continued_extent = None;
		self.facts.verified_stage_digest = None;
		self.facts.metadata = None;
		self.phases.clear();
	}

	pub(in crate::remote_download) fn note_progress(
		&mut self,
		active: &RemoteContinuedCapture,
		kind: FrameKind,
	) {
		if kind == FrameKind::RemoteCaptureContinued {
			self.continued_passes += 1;
			self.facts.phase = Some(Phase::ContinuedCapture);
		}
		self.facts.continued_extent = StreamLength::new(active.covered_end()).ok();
	}

	pub(in crate::remote_download) fn note_failure(&mut self, failure: RemoteRecordedUncertainty) {
		self.facts.phase = Some(Phase::Uncertain);
		self.facts.failure = Some(failure);
	}

	// Selected witnessed branch per-kind admission before the framing reader
	// allocates a payload. An absent cap denotes an impossible successor.
	pub(in crate::remote_download) fn payload_cap(&self, kind: FrameKind) -> Option<usize> {
		use FrameKind as K;
		let allowed = match self.facts.phase? {
			Phase::ContinuedCapture => matches!(
				kind,
				K::RangeCheckpoint
					| K::RemoteCaptureContinued
					| K::RemoteCaptureRetired
					| K::RemoteWitnessIntent
					| K::FailureRecorded
			),
			Phase::WitnessIntentRequiresInspection => matches!(
				kind,
				K::StageSealed | K::RemoteCaptureRetired | K::FailureRecorded
			),
			Phase::Sealed => matches!(
				kind,
				K::VerificationRecorded | K::RemoteCaptureRetired | K::FailureRecorded
			),
			Phase::Verified => matches!(
				kind,
				K::MetadataRecorded | K::RemoteCaptureRetired | K::FailureRecorded
			),
			Phase::MetadataReady => matches!(
				kind,
				K::PublishIntent | K::RemoteCaptureRetired | K::FailureRecorded
			),
			Phase::PublishIntentRequiresObservation => kind == K::PublishObserved,
			Phase::PublishedObserved => kind == K::DurabilityRecorded,
			Phase::Durable => kind == K::RemoteReceiptReady,
			Phase::ReceiptReadyRequiresInspection => kind == K::ReceiptCommitted,
			Phase::Retired => kind == K::RemoteStageAllocated,
			_ => false,
		};
		if !allowed {
			return None;
		}
		match kind {
			K::RemoteWitnessIntent => Some(MAX_REMOTE_WITNESS_INTENT_BYTES),
			K::RemoteReceiptReady => Some(MAX_REMOTE_RECEIPT_READY_BYTES),
			K::RemoteCaptureContinued => {
				Some(crate::remote_download::continuation::MAX_REMOTE_CONTINUATION_PAYLOAD_BYTES)
			}
			K::RangeCheckpoint | K::FailureRecorded | K::RemoteStageAllocated => {
				Some(crate::remote_download::MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES)
			}
			_ => Record::payload_cap(kind),
		}
	}

	pub(in crate::remote_download) fn accept(
		&mut self,
		trust: &RemoteBootstrapTrust<'_>,
		prior: &RemoteDownloadReplay,
		active: &RemoteContinuedCapture,
		frame: Frame,
		end: RemoteReplayBoundary,
	) -> Result<(), RemoteReplayMismatch> {
		self.accept_frame(trust, prior, active, frame, end)
			.map_err(RemoteReplayMismatch::Payload)
	}

	fn accept_frame(
		&mut self,
		trust: &RemoteBootstrapTrust<'_>,
		prior: &RemoteDownloadReplay,
		active: &RemoteContinuedCapture,
		frame: Frame,
		end: RemoteReplayBoundary,
	) -> Result<(), Error> {
		let previous = prior.boundary();
		match frame.kind() {
			FrameKind::RemoteWitnessIntent => {
				let coverage = active.coverage_predecessor(previous, true)?;
				let witness = archive::from_archived_intent(
					trust,
					&frame,
					end,
					coverage,
					self.qualification,
					self.grant,
				)?;
				self.facts.witness = Some(witness);
				self.facts.phase = Some(Phase::WitnessIntentRequiresInspection);
				self.phases.push(frame);
				return Ok(());
			}
			FrameKind::RemoteReceiptReady => return self.accept_ready(prior, &frame, end),
			_ => {}
		}
		let binding = if let Some(witness) = self.facts.witness {
			witness.binding()
		} else {
			let coverage = active.coverage_predecessor(previous, false)?;
			let (continuation, predecessor) = coverage.authenticated(trust)?;
			binding_for(continuation, predecessor, previous)?
		};
		let body = Record::from_frame(&frame, end, binding, previous)?.body();
		match body {
			Body::Retire { .. } => {
				let retained = validation::retirement(self, trust, prior, binding, body)?;
				self.facts.retirements.push(RemoteWitnessedRetirement {
					head: end.head,
					binding,
					witness: retained,
				});
				self.facts.phase = Some(Phase::Retired);
			}
			body => {
				let phase = validation::closeout(self, trust, body)?;
				match body {
					Body::Verify { stage, .. } => self.facts.verified_stage_digest = Some(stage),
					Body::Metadata(metadata) => self.facts.metadata = Some(metadata),
					Body::Observed(outcome) => {
						self.facts.outcome = Some(outcome);
						self.observed = Some(end);
					}
					Body::CommittedReceipt { .. } => {
						self.facts.committed_destination =
							Some(trust.owner().manifest().scope.destination.clone());
					}
					_ => {}
				}
				if phase == Phase::Durable {
					self.facts.receipt_cut = Some(receipt::Cut {
						durable: end,
						metadata: self.head(FrameKind::MetadataRecorded)?,
						observed: self.observed.ok_or(Error::FrameBinding)?,
					});
				}
				self.facts.phase = Some(phase);
				if matches!(
					phase,
					Phase::Sealed
						| Phase::Verified
						| Phase::MetadataReady
						| Phase::PublishIntentRequiresObservation
						| Phase::PublishedObserved
						| Phase::Durable
				) {
					self.phases.push(frame);
				}
			}
		}
		Ok(())
	}

	fn accept_ready(
		&mut self,
		prior: &RemoteDownloadReplay,
		frame: &Frame,
		end: RemoteReplayBoundary,
	) -> Result<(), Error> {
		let witness = self.facts.witness.ok_or(Error::FrameBinding)?;
		let boundary = prior.boundary();
		let inode = archive::receipt_inode(frame, witness, boundary)?;
		receipt::check_receipt_inode(prior.attempts(), inode)?;
		let cut = self.facts.receipt_cut.ok_or(Error::FrameBinding)?;
		if cut.durable != boundary {
			return Err(Error::FrameBinding);
		}
		let receipt = receipt::Artifact::from_frames(witness, &self.phases)?;
		let durability = self.phases.last().ok_or(Error::FrameBinding)?;
		let expected = receipt.expectation(witness, cut, durability, inode);
		let ready = RemoteReceiptReady::from_frame(frame, end, &expected)?;
		self.facts.ready = Some(ready);
		self.facts.receipt = Some(receipt);
		self.facts.phase = Some(Phase::ReceiptReadyRequiresInspection);
		Ok(())
	}

	fn head(&self, kind: FrameKind) -> Result<crate::frame::ChainHead, Error> {
		receipt::frame_head(&self.phases, kind)
	}
}
