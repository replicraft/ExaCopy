use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	MetadataRecorded, OwnerRecord, PublicationOutcome, PublishIntent, PublishIntentContext,
	RecoveryDecisionFrames, RecoveryDirectories, RecoveryStarted, RetainedPublicationDecision,
	VerificationRecorded,
};

use super::super::{JournalReplay, JournalReplayError};
use super::{LocalCopyPlan, PublicationFrames, check_stage_directory, require_binding};

pub(super) struct PendingRetry {
	started: Frame,
	verification: Frame,
	metadata: Option<Frame>,
	decision: Option<RetainedPublicationDecision>,
}

impl PendingRetry {
	pub(super) fn new(
		started: Frame,
		frame: Frame,
		summary: &JournalReplay,
	) -> Result<Self, JournalReplayError> {
		let start = RecoveryStarted::from_frame(&started)?;
		let fresh = VerificationRecorded::from_frame(&frame)?;
		require_binding(
			frame.kind(),
			summary.durability.is_none()
				&& !summary.published_recovery
				&& !matches!(
					summary.observation.map(|record| record.outcome()),
					Some(PublicationOutcome::Published { .. })
				)
				&& fresh.context == start.context()
				&& fresh.entry == start.entry()
				&& summary.verification.is_some_and(|prior| {
					fresh.source() == prior.source() && fresh.stage() == prior.stage()
				}),
		)?;
		Ok(Self {
			started,
			verification: frame,
			metadata: None,
			decision: None,
		})
	}

	pub(super) fn metadata(
		&mut self,
		frame: Frame,
		summary: &JournalReplay,
	) -> Result<(), JournalReplayError> {
		let start = RecoveryStarted::from_frame(&self.started)?;
		let fresh = MetadataRecorded::from_frame(&frame)?;
		require_binding(
			frame.kind(),
			self.metadata.is_none()
				&& fresh.context == start.context()
				&& fresh.entry == start.entry()
				&& summary.metadata.is_some_and(|prior| {
					fresh.stage == prior.stage && fresh.metadata == prior.metadata
				}),
		)?;
		self.metadata = Some(frame);
		Ok(())
	}

	pub(super) fn decide(
		&mut self,
		frame: &Frame,
		prior: &Frame,
		summary: &mut JournalReplay,
		plan: &LocalCopyPlan<'_>,
		owner: &OwnerRecord,
	) -> Result<(), JournalReplayError> {
		let Some(metadata) = &self.metadata else {
			return binding_error(frame.kind());
		};
		let decision = RetainedPublicationDecision::from_frame(frame)?;
		let stage_dir = decision.evidence().directories.stage;
		require_binding(
			frame.kind(),
			self.decision.is_none()
				&& summary
					.recovery_stage_directory
					.is_none_or(|previous| stage_dir == previous),
		)?;
		check_stage_directory(frame.kind(), stage_dir, plan, owner)?;
		decision.validate_evidence(
			RecoveryDecisionFrames {
				started: &self.started,
				intent: prior,
				verification: &self.verification,
				metadata,
			},
			owner.digest(),
			RecoveryDirectories {
				stage: stage_dir,
				destination: plan.destination().root.identity,
			},
			plan.source().file_identity,
			summary.last_effect_sequence,
		)?;

		summary.recovery_stage_directory = Some(stage_dir);
		summary.last_effect_sequence = decision.effect_sequence();
		self.decision = Some(decision);
		Ok(())
	}

	pub(super) fn accept_intent(
		self,
		frame: Frame,
		prior: &Frame,
		summary: &mut JournalReplay,
	) -> Result<PublicationFrames, JournalReplayError> {
		let (Some(metadata), Some(decision)) = (self.metadata, self.decision) else {
			return binding_error(frame.kind());
		};
		let fresh = PublishIntent::from_frame(&frame)?;
		let prior = PublishIntent::from_frame(prior)?;
		let verification = VerificationRecorded::from_frame(&self.verification)?;
		let context = decision.context();
		require_binding(
			frame.kind(),
			fresh.context
				== (PublishIntentContext {
					job: context.job,
					epoch: context.epoch,
					entry: decision.entry(),
					effect_sequence: decision.effect_sequence(),
					plan_digest: context.plan_digest,
				})
				&& fresh.target.stage == prior.target.stage
				&& fresh.target.parent == prior.target.parent
				&& fresh.target.component == prior.target.component
				&& fresh.target.primitive == prior.target.primitive
				&& fresh.target.verification_digest == verification.record_digest(),
		)?;
		summary.verification = Some(verification);
		summary.verification_head = Some(self.verification.head());
		summary.metadata = Some(MetadataRecorded::from_frame(&metadata)?);
		summary.metadata_head = Some(metadata.head());
		summary.intent = Some(fresh.context);
		summary.intent_head = Some(frame.head());
		summary.observation = None;
		summary.observation_head = None;
		Ok(PublicationFrames {
			verification: self.verification,
			metadata,
			intent: frame,
		})
	}

	pub(super) fn expected(&self) -> FrameKind {
		if self.metadata.is_none() {
			FrameKind::MetadataRecorded
		} else if self.decision.is_none() {
			FrameKind::RecoveryDecision
		} else {
			FrameKind::PublishIntent
		}
	}
}

fn binding_error<T>(kind: FrameKind) -> Result<T, JournalReplayError> {
	Err(JournalReplayError::RecordBinding { kind })
}
