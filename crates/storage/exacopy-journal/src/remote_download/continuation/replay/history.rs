use crate::frame::{Frame, FrameKind};
use crate::remote_download::{
	RemoteDownloadBody, RemoteDownloadRecord, RemoteUncertainBoundary,
	checkpoints::RemoteActiveCheckpoints,
	continuation::{
		CoverageBasis, PriorPreparation, RemoteContinuationCoverage, RemoteContinuationPrior,
	},
	replay::RemoteReplayMismatch as Mismatch,
};

use super::super::checkpoint::RemoteContinuedCheckpoint;
use super::{
	Error, RemoteBootstrapTrust, RemoteContinuedCapture, RemoteDownloadReplay,
	RemoteFinalizationPhase, RemoteRecordedUncertainty, RemoteReplayBoundary,
	RemoteVerifiedCheckpoint, StreamLength, WitnessFrames,
};

/// Explicitly selected historical continuation state for the common scan loop.
pub(in crate::remote_download) struct ContinuedHistory {
	legacy_qualification: [u8; 32],
	qualification: [u8; 32],
	grant: [u8; 32],
	active: Option<RemoteContinuedCapture>,
	failure: Option<RemoteRecordedUncertainty>,
	retain_witness_frames: bool,
}

impl ContinuedHistory {
	pub(in crate::remote_download) const fn new(
		legacy_qualification: [u8; 32],
		qualification: [u8; 32],
		grant: [u8; 32],
		retain_witness_frames: bool,
	) -> Self {
		Self {
			legacy_qualification,
			qualification,
			grant,
			active: None,
			failure: None,
			retain_witness_frames,
		}
	}

	pub(in crate::remote_download) const fn active(&self) -> Option<&RemoteContinuedCapture> {
		self.active.as_ref()
	}

	pub(in crate::remote_download) const fn failure(&self) -> Option<RemoteRecordedUncertainty> {
		self.failure
	}

	pub(in crate::remote_download) fn accept(
		&mut self,
		prior: &mut RemoteDownloadReplay,
		phase: RemoteFinalizationPhase,
		trust: &RemoteBootstrapTrust<'_>,
		frame: Frame,
		end: RemoteReplayBoundary,
	) -> Result<(), Mismatch> {
		if self.failure.is_some() || prior.recorded_uncertainty().is_some() {
			return Err(Mismatch::AfterUncertainty);
		}
		if let Some(active) = &mut self.active {
			match frame.kind() {
				FrameKind::RangeCheckpoint => {
					active.accept_checkpoint(trust, prior.boundary(), frame, end)
				}
				FrameKind::FailureRecorded => {
					self.failure = Some(active.accept_failure(trust, prior.boundary(), &frame)?);
					active.witness_frames = None;
					Ok(())
				}
				_ => Err(Mismatch::UnsupportedKind),
			}
		} else {
			self.active = Some(self.accept_continuation(prior, phase, trust, frame, end)?);
			// The signed aggregate and old attempt summary now carry the lineage.
			prior.active_checkpoints = None;
			Ok(())
		}
	}

	pub(in crate::remote_download) fn select_fresh(&mut self, qualification: [u8; 32]) {
		self.legacy_qualification = qualification;
		self.active = None;
	}

	pub(in crate::remote_download) fn repeat(
		&mut self,
		prior: &RemoteDownloadReplay,
		trust: &RemoteBootstrapTrust<'_>,
		frame: Frame,
		end: RemoteReplayBoundary,
	) -> Result<(), Mismatch> {
		let old = self.active.as_ref().ok_or(Mismatch::Order)?;
		let previous = prior.boundary();
		let coverage = old
			.coverage_predecessor(previous, false)
			.map_err(Mismatch::Payload)?;
		let (old_continuation, _) = coverage.authenticated(trust).map_err(Mismatch::Payload)?;
		let prior_claims = old_continuation.claims();
		let source_extent = old.source.length();
		let claims = trust
			.verify_continuation_frame(&frame, previous, end, source_extent)
			.map_err(Mismatch::Payload)?
			.claims();
		let expected_prior = RemoteContinuationPrior {
			active: PriorPreparation::Continued(old.admitted_at.head),
			epochs: old.epochs,
			..prior_claims.prior
		};
		let basis = old.checkpoints.last().map_or(
			CoverageBasis::ContinuedPrefix(old.admitted_at.head),
			|row| CoverageBasis::Checkpoint {
				head: row.head(),
				ordinal: row.ordinal(),
			},
		);
		let expected_coverage = RemoteContinuationCoverage {
			basis,
			end: StreamLength::new(old.covered_end).map_err(|_| Mismatch::Checkpoint)?,
		};
		if claims.prior != expected_prior
			|| claims.directory != prior_claims.directory
			|| claims.stage != prior_claims.stage
		{
			return Err(Mismatch::StageBinding);
		}
		if claims.coverage != expected_coverage {
			return Err(Mismatch::Checkpoint);
		}
		if claims.qualification_digest != self.qualification || claims.grant_digest != self.grant {
			return Err(Mismatch::Payload(Error::Binding));
		}
		let epochs = claims.epochs;
		let source = claims.source;
		let adopted_end = claims.adopted_end;
		let prefix_digest = claims.prefix_digest;
		self.active = Some(RemoteContinuedCapture {
			frame,
			admitted_at: end,
			epochs,
			source,
			adopted_end,
			prefix_digest,
			checkpoints: Vec::new(),
			covered_end: adopted_end.get(),
			witness_frames: Some(WitnessFrames {
				original_boundary: previous,
				original_source_extent: source_extent,
				latest: None,
			}),
		});
		Ok(())
	}

	fn accept_continuation(
		&self,
		prior: &RemoteDownloadReplay,
		phase: RemoteFinalizationPhase,
		trust: &RemoteBootstrapTrust<'_>,
		frame: Frame,
		end: RemoteReplayBoundary,
	) -> Result<RemoteContinuedCapture, Mismatch> {
		if phase != RemoteFinalizationPhase::Capture {
			return Err(Mismatch::Order);
		}
		let bootstrap = prior
			.stage_directory_prepared()
			.ok_or(Mismatch::BootstrapRequired)?;
		let old = RemoteActiveCheckpoints::from_replay(
			trust.owner(),
			prior,
			phase,
			self.legacy_qualification,
		)
		.map_err(Mismatch::Payload)?;
		let latest = old.checkpoints().last().ok_or(Mismatch::Checkpoint)?;
		let expected_head = old.prepared();
		let previous = old.boundary();
		let original_source_extent = old.source().length();
		let claims = trust
			.verify_continuation_frame(&frame, previous, end, original_source_extent)
			.map_err(Mismatch::Payload)?
			.claims();

		let expected_prior = RemoteContinuationPrior {
			bootstrap: bootstrap.head(),
			allocation: old.allocation(),
			prepared: expected_head.head,
			active: PriorPreparation::Original(expected_head.head),
			epochs: old.epochs(),
			name: exacopy_endpoint::UnixComponent::new(old.name())
				.map_err(|_| Mismatch::StageBinding)?,
			nonce: *old.nonce(),
		};
		if claims.prior != expected_prior
			|| claims.directory != expected_head.directory
			|| claims.directory != bootstrap.directory()
			|| claims.stage != expected_head.file
		{
			return Err(Mismatch::StageBinding);
		}
		let expected_coverage = RemoteContinuationCoverage {
			basis: CoverageBasis::Checkpoint {
				head: latest.head(),
				ordinal: latest.ordinal(),
			},
			end: StreamLength::new(old.covered_extent()).map_err(|_| Mismatch::Checkpoint)?,
		};
		if claims.coverage != expected_coverage {
			return Err(Mismatch::Checkpoint);
		}
		if claims.qualification_digest != self.qualification || claims.grant_digest != self.grant {
			return Err(Mismatch::Payload(Error::Binding));
		}
		let epochs = claims.epochs;
		let source = claims.source;
		let adopted_end = claims.adopted_end;
		let prefix_digest = claims.prefix_digest;
		Ok(RemoteContinuedCapture {
			frame,
			admitted_at: end,
			epochs,
			source,
			adopted_end,
			prefix_digest,
			checkpoints: Vec::new(),
			covered_end: adopted_end.get(),
			witness_frames: self.retain_witness_frames.then_some(WitnessFrames {
				original_boundary: previous,
				original_source_extent,
				latest: None,
			}),
		})
	}
}

impl RemoteContinuedCapture {
	fn accept_checkpoint(
		&mut self,
		trust: &RemoteBootstrapTrust<'_>,
		previous: RemoteReplayBoundary,
		frame: Frame,
		boundary: RemoteReplayBoundary,
	) -> Result<(), Mismatch> {
		let checkpoint =
			RemoteContinuedCheckpoint::from_frame(&frame).map_err(Mismatch::Payload)?;
		let range = checkpoint.range();
		if checkpoint.context()
			!= crate::remote_download::RemoteDownloadContext::for_owner(trust.owner())
		{
			return Err(Mismatch::Context);
		}
		if checkpoint.predecessor() != previous.head {
			return Err(Mismatch::Predecessor);
		}
		if checkpoint.continuation() != self.admitted_at.head
			|| checkpoint.epochs() != self.epochs
			|| usize::from(range.ordinal) != self.checkpoints.len() + 1
			|| range.offset != self.covered_end
		{
			return Err(Mismatch::Checkpoint);
		}
		let end = range
			.offset
			.checked_add(range.length)
			.filter(|end| *end <= self.source.length().get())
			.ok_or(Mismatch::Checkpoint)?;
		self.checkpoints.push(RemoteVerifiedCheckpoint::new(
			frame.head(),
			range.ordinal,
			range.offset,
			range.length,
			range.digest,
		));
		self.covered_end = end;
		if let Some(frames) = &mut self.witness_frames {
			frames.latest = Some((frame, boundary));
		}
		Ok(())
	}

	pub(in crate::remote_download) fn accept_failure(
		&self,
		trust: &RemoteBootstrapTrust<'_>,
		previous: RemoteReplayBoundary,
		frame: &Frame,
	) -> Result<RemoteRecordedUncertainty, Mismatch> {
		let record = RemoteDownloadRecord::from_frame(frame).map_err(Mismatch::Payload)?;
		if record.context()
			!= crate::remote_download::RemoteDownloadContext::for_owner(trust.owner())
		{
			return Err(Mismatch::Context);
		}
		if record.predecessor() != Some(previous.head) {
			return Err(Mismatch::Predecessor);
		}
		let RemoteDownloadBody::FailureRecorded {
			attempt,
			epochs,
			boundary,
		} = record.body()
		else {
			return Err(Mismatch::FailureBinding);
		};
		if attempt != self.admitted_at.head
			|| epochs != self.epochs
			|| boundary == RemoteUncertainBoundary::Creation
		{
			return Err(Mismatch::FailureBinding);
		}
		Ok(RemoteRecordedUncertainty {
			head: frame.head(),
			attempt,
			epochs,
			boundary,
		})
	}
}
