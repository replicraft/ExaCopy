use std::io::Read;

use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	EntryPreparation, JournalContext, MetadataRecorded, ObservedTimestamp, OwnerRecord,
	OwnerStateDirectory, OwnerTimestamp, PublishIntent, RangeResumeStarted, StageSealed,
	VerificationRecorded,
};

use super::suffix::PublicationFrames;
use super::{JournalReplayError, LocalCopyPlan, Scan, publication_context, require_binding};

enum Next {
	Seal,
	Verify(StageSealed),
	Metadata(Frame, VerificationRecorded),
	Intent(Frame, VerificationRecorded, Frame),
}

impl Next {
	const fn kind(&self) -> FrameKind {
		match self {
			Self::Seal => FrameKind::StageSealed,
			Self::Verify(_) => FrameKind::VerificationRecorded,
			Self::Metadata(_, _) => FrameKind::MetadataRecorded,
			Self::Intent(_, _, _) => FrameKind::PublishIntent,
		}
	}
}

impl<R: Read> Scan<R> {
	pub(super) fn replay_preintent(
		&mut self,
		mut next: Option<Frame>,
		plan: &LocalCopyPlan<'_>,
		owner: &OwnerRecord,
		prepared: EntryPreparation<'_>,
	) -> Result<(), JournalReplayError> {
		let entry = plan.attempt().entry;
		let mut expected = Next::Seal;
		while let Some(frame) = next {
			let kind = frame.kind();
			if kind == FrameKind::RecoveryStarted && !self.summary.checkpoints.is_empty() {
				self.start_range_resume(&frame, plan, owner, prepared)?;
				expected = Next::Seal;
			} else {
				let context = JournalContext {
					epoch: self.summary.latest_epoch,
					..plan.context()
				};
				if kind != expected.kind() {
					return Err(JournalReplayError::UnexpectedRecord {
						expected: Some(expected.kind()),
						found: kind,
					});
				}
				expected = match expected {
					Next::Seal => {
						let seal = StageSealed::from_frame(&frame)?;
						require_binding(
							kind,
							seal.context == context
								&& seal.entry == entry
								&& seal.stage == prepared.stage
								&& seal.length.get() == prepared.source.length(),
						)?;
						self.summary.sealed = Some(seal);
						Next::Verify(seal)
					}
					Next::Verify(seal) => {
						let record = VerificationRecorded::from_frame(&frame)?;
						require_binding(
							kind,
							record.context == context
								&& record.entry == entry
								&& record.source().identity == prepared.source.identity()
								&& record.stage().identity == prepared.stage
								&& record.source().length == seal.length
								&& record.stage().length == seal.length,
						)?;
						self.summary.verification = Some(record);
						self.summary.verification_head = Some(frame.head());
						Next::Metadata(frame, record)
					}
					Next::Metadata(verification_frame, verification) => {
						let record = MetadataRecorded::from_frame(&frame)?;
						let source_times = prepared.source.times();
						require_binding(
							kind,
							record.context == context
								&& record.entry == entry
								&& record.stage == prepared.stage
								&& record.metadata.mode() == prepared.source_metadata.mode()
								&& record.metadata.uid == prepared.source_metadata.owner()
								&& record.metadata.gid == prepared.source_metadata.group()
								&& same_time(record.metadata.accessed_at, source_times.accessed_at)
								&& same_time(record.metadata.modified_at, source_times.modified_at),
						)?;
						self.summary.metadata = Some(record);
						self.summary.metadata_head = Some(frame.head());
						Next::Intent(verification_frame, verification, frame)
					}
					Next::Intent(verification_frame, verification, metadata) => {
						let intent = PublishIntent::from_frame(&frame)?;
						let destination = plan.destination();
						require_binding(
							kind,
							intent.context == publication_context(context, entry)
								&& intent.target.stage == prepared.stage
								&& intent.target.parent == destination.root.identity
								&& intent.target.component == destination.component
								&& intent.target.verification_digest
									== verification.record_digest(),
						)?;
						self.summary.intent = Some(intent.context);
						self.summary.intent_head = Some(frame.head());
						self.summary.last_effect_sequence = intent.context.effect_sequence;
						return self.replay_suffix(
							PublicationFrames {
								verification: verification_frame,
								metadata,
								intent: frame,
							},
							plan,
							owner,
						);
					}
				};
			}
			next = self.read_next()?;
		}
		Ok(())
	}

	fn start_range_resume(
		&mut self,
		frame: &Frame,
		plan: &LocalCopyPlan<'_>,
		owner: &OwnerRecord,
		prepared: EntryPreparation<'_>,
	) -> Result<(), JournalReplayError> {
		let record = RangeResumeStarted::from_frame(frame)?;
		let context = record.context();
		let recorded = record.evidence();
		let destination = plan.destination().root.identity;
		let kind = frame.kind();
		require_binding(
			kind,
			context.job == plan.context().job
				&& context.plan_digest == plan.digest()
				&& record.entry() == plan.attempt().entry
				&& record.prior_epoch() == self.summary.latest_epoch
				&& Some(recorded.preparation) == self.summary.preparation_head
				&& recorded.authorization == owner.digest()
				&& recorded.stage == prepared.stage
				&& recorded.stage_directory != destination
				&& self
					.summary
					.recovery_stage_directory
					.is_none_or(|known| known == recorded.stage_directory)
				&& owner
					.manifest()
					.directories
					.contains(&OwnerStateDirectory::Receipts),
		)?;
		super::suffix::check_stage_directory(kind, recorded.stage_directory, plan, owner)?;
		// Each fresh pre-intent run must earn its own verification and metadata.
		self.summary.latest_epoch = context.epoch;
		self.summary.recovery_stage_directory = Some(recorded.stage_directory);
		self.summary.sealed = None;
		self.summary.verification = None;
		self.summary.verification_head = None;
		self.summary.metadata = None;
		self.summary.metadata_head = None;
		Ok(())
	}
}

fn same_time(actual: OwnerTimestamp, source: ObservedTimestamp) -> bool {
	actual.seconds() == source.seconds() && actual.nanoseconds() == source.nanoseconds()
}
