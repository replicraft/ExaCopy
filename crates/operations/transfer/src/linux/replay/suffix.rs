use std::io::Read;

use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	DurabilityRecorded, LinuxFileIdentity, OwnerRecord, OwnerStateDirectory, PublicationOutcome,
	PublishObserved, ReceiptCommitted, RecoveryDecision, RecoveryDecisionFrames,
	RecoveryDirectories, RecoveryStarted,
};

use super::{JournalReplayError, JournalTail, LocalCopyPlan, Scan, require_binding};

mod retry;
use retry::PendingRetry;

pub(super) struct PublicationFrames {
	pub(super) verification: Frame,
	pub(super) metadata: Frame,
	pub(super) intent: Frame,
}

enum RecoveryGeneration {
	None,
	Started(Frame),
	Decided,
	Retry(Box<PendingRetry>),
}

impl<R: Read> Scan<R> {
	pub(super) fn replay_suffix(
		&mut self,
		mut active: PublicationFrames,
		plan: &LocalCopyPlan<'_>,
		owner: &OwnerRecord,
	) -> Result<(), JournalReplayError> {
		let mut generation = RecoveryGeneration::None;
		let mut observation_frame: Option<Frame> = None;
		let owner_digest = owner.digest();
		let receipts_owned = owner
			.manifest()
			.directories
			.contains(&OwnerStateDirectory::Receipts);

		while let Some(frame) = self.read_next()? {
			match frame.kind() {
				FrameKind::RecoveryStarted => {
					let started = RecoveryStarted::from_frame(&frame)?;
					started.validate_intent(&active.intent, owner_digest)?;
					require_binding(
						frame.kind(),
						receipts_owned
							&& started.prior_epoch() == self.summary.latest_epoch
							&& !matches!(
								self.summary.observation.map(|record| record.outcome()),
								Some(PublicationOutcome::NotPerformed { .. })
							),
					)?;
					self.summary.latest_epoch = started.context().epoch;
					generation = RecoveryGeneration::Started(frame);
				}
				FrameKind::VerificationRecorded => {
					let RecoveryGeneration::Started(started) = generation else {
						return Err(JournalReplayError::RecordBinding { kind: frame.kind() });
					};
					generation = RecoveryGeneration::Retry(Box::new(PendingRetry::new(
						started,
						frame,
						&self.summary,
					)?));
				}
				FrameKind::MetadataRecorded => {
					let RecoveryGeneration::Retry(pending) = &mut generation else {
						return Err(JournalReplayError::RecordBinding { kind: frame.kind() });
					};
					pending.metadata(frame, &self.summary)?;
				}
				FrameKind::RecoveryDecision => {
					if let RecoveryGeneration::Retry(pending) = &mut generation {
						pending.decide(&frame, &active.intent, &mut self.summary, plan, owner)?;
						continue;
					}
					let RecoveryGeneration::Started(started) = &generation else {
						return Err(JournalReplayError::RecordBinding { kind: frame.kind() });
					};
					let decision = RecoveryDecision::from_frame(&frame)?;
					let stage_directory = decision.evidence().stage_directory;
					// Earlier valid evidence binds the historical directory when present.
					// The recovery caller separately checks this claim against its live handle.
					let recorded_stage_directory = self.summary.recovery_stage_directory.or(self
						.summary
						.durability
						.map(|record| record.barriers().stage_directory));
					decision.validate_evidence(
						RecoveryDecisionFrames {
							started,
							intent: &active.intent,
							verification: &active.verification,
							metadata: &active.metadata,
						},
						owner_digest,
						RecoveryDirectories {
							stage: recorded_stage_directory.unwrap_or(stage_directory),
							destination: plan.destination().root.identity,
						},
					)?;
					check_stage_directory(frame.kind(), stage_directory, plan, owner)?;

					self.summary.recovery_stage_directory = Some(stage_directory);
					self.summary.published_recovery = true;
					generation = RecoveryGeneration::Decided;
				}
				FrameKind::PublishIntent => {
					let RecoveryGeneration::Retry(pending) = generation else {
						return Err(JournalReplayError::RecordBinding { kind: frame.kind() });
					};
					active = pending.accept_intent(frame, &active.intent, &mut self.summary)?;
					observation_frame = None;
					generation = RecoveryGeneration::None;
				}
				FrameKind::PublishObserved => {
					let observed = PublishObserved::from_frame(&frame)?;
					observed.validate_intent(&active.intent)?;
					let previous = self.summary.observation.map(|record| record.outcome());
					let compatible = match generation {
						RecoveryGeneration::None => previous.is_none(),
						RecoveryGeneration::Started(_) | RecoveryGeneration::Retry(_) => false,
						RecoveryGeneration::Decided => {
							matches!(previous, None | Some(PublicationOutcome::Uncertain { .. }))
								&& matches!(
									observed.outcome(),
									PublicationOutcome::Published { .. }
								)
						}
					};
					require_binding(frame.kind(), compatible)?;
					self.summary.observation = Some(observed);
					self.summary.observation_head = Some(frame.head());
					observation_frame = Some(frame);
				}
				FrameKind::DurabilityRecorded => {
					let Some(observed) = &observation_frame else {
						return Err(JournalReplayError::RecordBinding { kind: frame.kind() });
					};
					require_binding(
						frame.kind(),
						matches!(
							generation,
							RecoveryGeneration::None | RecoveryGeneration::Decided
						) && self.summary.durability.is_none(),
					)?;
					let durability = DurabilityRecorded::from_frame(&frame)?;
					durability.validate_evidence(&active.metadata, &active.intent, observed)?;
					let stage_directory = durability.barriers().stage_directory;
					check_stage_directory(frame.kind(), stage_directory, plan, owner)?;
					require_binding(
						frame.kind(),
						self.summary
							.recovery_stage_directory
							.is_none_or(|identity| identity == stage_directory),
					)?;
					self.summary.durability = Some(durability);
					self.summary.durability_head = Some(frame.head());
				}
				FrameKind::ReceiptCommitted => {
					let (Some(durability), Some(head)) =
						(self.summary.durability, self.summary.durability_head)
					else {
						return Err(JournalReplayError::RecordBinding { kind: frame.kind() });
					};
					let receipt = ReceiptCommitted::from_frame(&frame)?;
					require_binding(
						frame.kind(),
						matches!(
							generation,
							RecoveryGeneration::None | RecoveryGeneration::Decided
						) && receipt.context() == durability.context()
							&& receipt.durability() == head
							&& owner
								.manifest()
								.directories
								.contains(&OwnerStateDirectory::Receipts),
					)?;
					self.summary.receipt = Some(receipt);
					self.next(None)?;
					if matches!(self.summary.tail, JournalTail::Torn { .. }) {
						return Err(JournalReplayError::TrailingAfterReceipt);
					}
					return Ok(());
				}
				found => {
					let expected = match generation {
						RecoveryGeneration::Started(_) => FrameKind::RecoveryDecision,
						RecoveryGeneration::Retry(ref pending) => pending.expected(),
						_ if self.summary.durability.is_some() => FrameKind::ReceiptCommitted,
						_ if self.summary.observation.is_some() => FrameKind::DurabilityRecorded,
						_ => FrameKind::PublishObserved,
					};
					return Err(JournalReplayError::UnexpectedRecord {
						expected: Some(expected),
						found,
					});
				}
			}
		}

		Ok(())
	}
}

fn check_stage_directory(
	kind: FrameKind,
	stage_directory: LinuxFileIdentity,
	plan: &LocalCopyPlan<'_>,
	owner: &OwnerRecord,
) -> Result<(), JournalReplayError> {
	let source = plan.source();
	require_binding(
		kind,
		stage_directory != owner.manifest().state_root
			&& stage_directory != source.file_identity
			&& stage_directory != source.root_identity,
	)
}
