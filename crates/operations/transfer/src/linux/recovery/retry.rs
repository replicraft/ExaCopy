use exacopy_content::{measure_at, validate_stream_input};
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DurableJournal, JournalContext, JournalEpoch, PublicationOutcome, PublicationPrimitive,
	PublishIntent, PublishIntentContext, PublishIntentTarget, PublishObserved, RecoveryDirectories,
	RecoveryStartEvidence, RecoveryStarted, RetainedPublicationDecision,
	RetainedPublicationEvidence, RootCapabilityId, VerificationRecorded,
};
use exacopy_model::{
	CopyBinding, CopyEffect, CopyEvent, CopySession, EntryId, JobId, RunEpoch, StageId,
};
use exacopy_platform::linux::{
	DestinationRoot, ReadRoot, RecoveryInventory, RecoveryWriteLease, SourceFile,
};

use super::super::{LocalCopyPlan, StageFailure, check_source, observe};
use super::classify::verify;
use super::finish::{acquire_lease, append, completion, finish_leased, required};
use super::{
	RecoveryDisposition, RecoveryFinishError, RecoveryHistory, RecoveryInspectError,
	RecoveryInspection, RecoveryIssue, RecoveryProfile, RecoveryStep, native_identity,
};

mod error;
pub use error::RecoveryRetryError;

/// The current source-directory grant for this retained copy.
#[derive(Clone, Copy)]
pub struct RecoverySource<'root> {
	/// A held directory opened with current authority to read the source.
	pub root: &'root ReadRoot,
	/// The source capability ID independently assigned by the caller.
	pub id: RootCapabilityId,
}

/// Retries the no-clobber publication of a retained, sealed Linux stage.
///
/// The source grant and fresh source read must match the accepted copy history. An exclusive
/// recovery lease, freshly checked private stage, and new synchronized publication intent
/// are required before publication. If the target is already published, recovery can finish
/// its existing receipt under the same lease without another namespace mutation.
///
/// # Errors
/// Conflicting or incomplete evidence leaves existing files and journal records available
/// for inspection. An ambiguous effect must be reconciled against current filesystem state.
pub fn retry_recovery(
	destination: &DestinationRoot,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	source: RecoverySource<'_>,
	scratch: &mut [u8],
) -> Result<RecoveryInspection, RecoveryRetryError> {
	validate_stream_input(0, scratch.len()).map_err(RecoveryInspectError::Input)?;
	let lease = acquire_lease(destination, name)?;
	let job = lease.job();
	let history = RecoveryHistory::load(job, name, profile)?;
	let plan = history.plan()?;
	let names = job
		.inventory(plan.attempt().stage_name, plan.destination().component)
		.map_err(RecoveryStep::Namespace.platform())?;
	let current = history.inspect(job, &names, scratch)?;
	match current.disposition {
		RecoveryDisposition::PossibleRetry => {
			Retry {
				history: &history,
				plan,
				names: &names,
			}
			.publish(&lease, source, scratch)?;
		}
		RecoveryDisposition::PublishedNeedsBarriers
		| RecoveryDisposition::PublishedNeedsReceipt { .. } => {}
		_ => return Ok(current),
	}

	finish_leased(&lease, name, profile, scratch)
		.map_err(|error| match error {
			RecoveryFinishError::Inspection(error) => RecoveryFinishError::Completion(error),
			error => error,
		})
		.map_err(RecoveryRetryError::Recovery)
}

struct Retry<'history, 'job> {
	history: &'history RecoveryHistory,
	plan: LocalCopyPlan<'history>,
	names: &'history RecoveryInventory<'job>,
}

impl Retry<'_, '_> {
	fn publish(
		&self,
		lease: &RecoveryWriteLease<'_>,
		source: RecoverySource<'_>,
		scratch: &mut [u8],
	) -> Result<(), RecoveryRetryError> {
		let journal = &self.history.journal;
		let stage_file = self
			.names
			.stage()
			.ok_or(RecoveryFinishError::IncompleteEvidence)?;
		let stage_directory = self
			.names
			.stage_directory_identity()
			.map(native_identity)
			.ok_or(RecoveryFinishError::IncompleteEvidence)?;
		let stage = native_identity(stage_file.identity());
		let source = self.open_source(source)?;
		let prior_intent = required(journal.intent_head)?;
		let prior_measurements = required(journal.verification)?;
		let mut metadata = required(journal.metadata)?;
		let epoch = JournalEpoch::new(
			journal
				.latest_epoch
				.get()
				.checked_add(1)
				.ok_or(RecoveryFinishError::EpochExhausted)?,
		);
		let effect_sequence = journal
			.last_effect_sequence
			.checked_add(1)
			.ok_or(RecoveryRetryError::EffectSequenceExhausted)?;
		let context = JournalContext {
			epoch,
			..self.plan.context()
		};
		let entry = self.plan.attempt().entry;
		let binding = CopyBinding::new(
			JobId::try_from_bytes(*context.job.as_bytes())
				.map_err(|_| RecoveryFinishError::IncompleteEvidence)?,
			EntryId::new(1),
			RunEpoch::new(epoch.get()),
			StageId::from_bytes(*entry.as_bytes()),
		);
		let mut session = CopySession::new(binding);
		observe(&mut session, binding, CopyEvent::RetainedStageReopened)
			.map_err(RecoveryRetryError::Model)?;
		observe(&mut session, binding, CopyEvent::WritersJoined)
			.map_err(RecoveryRetryError::Model)?;
		let capability = lease
			.prepare_retained_stage(self.names, binding)
			.map_err(completion(RecoveryStep::Namespace))?;
		observe(&mut session, binding, CopyEvent::DataFlushed)
			.map_err(RecoveryRetryError::Model)?;

		let digest = measure_at(source.len(), scratch, |offset, buffer| {
			source.read_exact_at(offset, buffer)
		})
		.map_err(RecoveryRetryError::MeasureSource)?;
		if digest.as_bytes() != prior_measurements.source().digest.as_bytes() {
			return Err(RecoveryRetryError::SourceMismatch);
		}
		if let Some(issue) = verify(
			stage_file,
			prior_measurements.stage(),
			Some(metadata),
			scratch,
		)? {
			return Err(RecoveryRetryError::Stage(issue));
		}
		let atime = stage_file.observation().accessed_at();
		if atime.seconds() != metadata.metadata.accessed_at.seconds()
			|| atime.nanoseconds() != metadata.metadata.accessed_at.nanoseconds()
		{
			return Err(RecoveryRetryError::Stage(RecoveryIssue::MetadataMismatch));
		}
		observe(&mut session, binding, CopyEvent::ReadbackVerified)
			.map_err(RecoveryRetryError::Model)?;
		observe(&mut session, binding, CopyEvent::MetadataReady)
			.map_err(RecoveryRetryError::Model)?;
		observe(&mut session, binding, CopyEvent::StageSealed)
			.map_err(RecoveryRetryError::Model)?;
		check_source(&source).map_err(RecoveryRetryError::SourcePolicy)?;
		self.names
			.recheck()
			.map_err(completion(RecoveryStep::Namespace))?;

		let fresh = VerificationRecorded::new(
			context,
			entry,
			prior_measurements.source(),
			prior_measurements.stage(),
		)
		.map_err(RecoveryRetryError::Verification)?;
		metadata.context = context;
		let segment = lease
			.open_first_segment_for_append(&self.history.journal_file)
			.map_err(completion(RecoveryStep::Journal))?;
		let mut writer = DurableJournal::resume_first_segment(
			segment,
			journal.boundary.head,
			journal.boundary.offset,
		)
		.map_err(RecoveryFinishError::Resume)?;
		let started = RecoveryStarted::new(
			context,
			entry,
			journal.latest_epoch,
			RecoveryStartEvidence {
				intent: prior_intent,
				preceding: journal.boundary.head,
				authorization: self.history.owner.digest(),
			},
		)
		.map_err(RecoveryFinishError::Decision)?;
		let start = append(&mut writer, FrameKind::RecoveryStarted, &started.encode())?;
		let verification = append(
			&mut writer,
			FrameKind::VerificationRecorded,
			&fresh.encode(),
		)?;
		let metadata = append(&mut writer, FrameKind::MetadataRecorded, &metadata.encode())?;
		let destination = self.plan.destination();
		let decision = RetainedPublicationDecision::new(
			context,
			entry,
			start.head(),
			RetainedPublicationEvidence {
				stage,
				directories: RecoveryDirectories {
					stage: stage_directory,
					destination: destination.root.identity,
				},
				verification: verification.head(),
				metadata: metadata.head(),
			},
			effect_sequence,
		)
		.map_err(RecoveryFinishError::Decision)?;
		let _ = append(&mut writer, FrameKind::RecoveryDecision, &decision.encode())?;
		let effect = PublishIntentContext {
			job: context.job,
			epoch,
			entry,
			effect_sequence,
			plan_digest: context.plan_digest,
		};
		let intent = PublishIntent {
			context: effect,
			target: PublishIntentTarget {
				stage,
				parent: destination.root.identity,
				component: destination.component,
				verification_digest: fresh.record_digest(),
				primitive: PublicationPrimitive::LinuxRenameNoReplace,
			},
		};
		let intent = append(&mut writer, FrameKind::PublishIntent, &intent.encode())?;
		check_source(&source).map_err(RecoveryRetryError::SourcePolicy)?;
		let Some(CopyEffect::PublishNoClobber(authorization)) = session
			.apply(binding, CopyEvent::PublishIntentRecorded)
			.map_err(StageFailure::from)
			.map_err(RecoveryRetryError::Model)?
		else {
			return Err(RecoveryRetryError::Model(StageFailure::UnexpectedEffect));
		};
		capability
			.publish_no_clobber(authorization)
			.map_err(RecoveryRetryError::Publish)?;
		let observed = PublishObserved::new(
			effect,
			intent.head(),
			PublicationOutcome::Published { target: stage },
		)
		.map_err(RecoveryFinishError::Publication)?;
		let _ = append(&mut writer, FrameKind::PublishObserved, &observed.encode())?;
		Ok(())
	}

	fn open_source(&self, grant: RecoverySource<'_>) -> Result<SourceFile, RecoveryRetryError> {
		let planned = self.plan.source();
		if grant.id != planned.root_id
			|| native_identity(grant.root.identity()) != planned.root_identity
		{
			return Err(RecoveryRetryError::SourceMismatch);
		}
		let source = grant
			.root
			.open_regular(planned.component)
			.map_err(RecoveryRetryError::OpenSource)?;
		let current = source.observation();
		let modified = current.modified_at();
		let changed = current.changed_at();
		let journal = &self.history.journal;
		let original = required(journal.metadata)?;
		if native_identity(source.identity()) != planned.file_identity
			|| current.len() != planned.length
			|| modified.seconds() != planned.modified_at.seconds()
			|| modified.nanoseconds() != planned.modified_at.nanoseconds()
			|| changed.seconds() != planned.changed_at.seconds()
			|| changed.nanoseconds() != planned.changed_at.nanoseconds()
			|| current.mode() != original.metadata.mode()
			|| current.owner() != original.metadata.uid
			|| current.group() != original.metadata.gid
			|| Some(current.link_count()) != journal.source_link_count
		{
			return Err(RecoveryRetryError::SourceMismatch);
		}
		check_source(&source).map_err(RecoveryRetryError::SourcePolicy)?;
		Ok(source)
	}
}
