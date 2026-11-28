use exacopy_endpoint::JournalSegment;
use exacopy_endpoint::linux_apply::{ApplyRecord, GuardedCopyJob, LocalApplyAdmission};
use exacopy_endpoint::linux_job::JobWorkspace;
use exacopy_endpoint::linux_publication::{FreshReceiptWorkspace, HeldFreshReceipt};
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DurabilityRecorded, DurableJournal, LinuxFileIdentity, LinuxPublicationBarriers,
	PublicApplyIntent, PublicationOutcome, PublishObserved, ReceiptCommitted, SyncedFrame,
};
use exacopy_model::{CopyBinding, CopyEvent, CopySession};

use super::super::super::records::RecordedSeal;
use super::{CheckedCopyError, PublicApplyIntentSelection, PublicApplyStageRequest, append};
use crate::linux::{
	CopyReceipt, MAX_PUBLIC_APPLY_RECEIPT_BYTES, PublicApplyCommitSelection, PublicApplyReceipt,
	ReceiptEvidence,
};

const MAX_SUFFIX_BYTES: usize = 4096;

pub(super) struct PublishedAttempt<'recorded, 'name> {
	pub(super) intent: PublicApplyIntent<'name>,
	pub(super) intent_frame: SyncedFrame,
	pub(super) recorded: RecordedSeal<'recorded>,
	pub(super) seal_frame: SyncedFrame,
	pub(super) stage_dir_identity: LinuxFileIdentity,
}

pub(super) struct ReceiptHold<Holder> {
	held: Holder,
	exact: Vec<u8>,
}

impl<Holder: HeldFreshReceipt> ReceiptHold<Holder> {
	fn read<R, P, C, A>(
		&self,
	) -> Result<[u8; MAX_PUBLIC_APPLY_RECEIPT_BYTES], CheckedCopyError<R, Holder::Error, P, C, A>>
	{
		let mut bytes = [0; MAX_PUBLIC_APPLY_RECEIPT_BYTES];
		self.held
			.read_exact_receipt(&mut bytes[..self.exact.len()])
			.map_err(CheckedCopyError::Artifact)?;
		if bytes[..self.exact.len()] != self.exact {
			return Err(CheckedCopyError::Binding);
		}
		Ok(bytes)
	}

	pub(super) fn read_again<R, P, C, A>(
		&self,
	) -> Result<(), CheckedCopyError<R, Holder::Error, P, C, A>> {
		self.read().map(|_| ())
	}
}

pub(super) struct Committed<'name, Holder> {
	pub(super) receipt: PublicApplyReceipt<'name>,
	pub(super) terminal: SyncedFrame,
	pub(super) receipt_hold: ReceiptHold<Holder>,
}

type Finish<'name, 'job, J, R, P, C, A> = Result<
	Committed<'name, <J as FreshReceiptWorkspace>::HeldReceipt<'job>>,
	CheckedCopyError<R, <J as JobWorkspace>::Error, P, C, A>,
>;

pub(super) fn commit<'name, 'job, J, R, P, C, A>(
	request: &PublicApplyStageRequest<'_, '_, 'name>,
	selection: PublicApplyIntentSelection,
	authority: &impl LocalApplyAdmission,
	job: &'job J,
	journal: &mut DurableJournal<J::Segment>,
	attempt: PublishedAttempt<'_, 'name>,
	model: (&mut CopySession, CopyBinding),
) -> Finish<'name, 'job, J, R, P, C, A>
where
	J: GuardedCopyJob,
	J::Segment: JournalSegment,
{
	let PublishedAttempt {
		intent,
		intent_frame,
		recorded,
		seal_frame,
		stage_dir_identity,
	} = attempt;
	let (session, model_binding) = model;
	let private = intent.private();
	let context = private.context;
	let stage = recorded.verification().stage();
	let owner = intent.association();
	let observed = PublishObserved::new(
		context,
		intent_frame.head(),
		PublicationOutcome::Published {
			target: stage.identity,
		},
	)
	.map_err(CheckedCopyError::Record)?;
	let (frame, observed_frame) = append(
		journal,
		FrameKind::PublishObserved,
		ApplyRecord::Observation,
		observed.encode(),
		authority,
	)
	.map_err(|cause| CheckedCopyError::Journal(FrameKind::PublishObserved, cause))?;
	if PublishObserved::from_frame(&frame).map_err(CheckedCopyError::Record)? != observed
		|| frame.previous_digest() != intent_frame.head().digest()
		|| intent_frame.head().sequence().checked_add(1) != Some(frame.head().sequence())
	{
		return Err(CheckedCopyError::Binding);
	}
	model_observation(session, model_binding, CopyEvent::Published)?;
	let durable = DurabilityRecorded::new(
		context,
		observed_frame.head(),
		LinuxPublicationBarriers {
			metadata: recorded.metadata.head(),
			stage_directory: stage_dir_identity,
			destination_directory: private.target.parent,
		},
	)
	.map_err(CheckedCopyError::Record)?;
	let (frame, durable_frame) = append(
		journal,
		FrameKind::DurabilityRecorded,
		ApplyRecord::Durability,
		durable.encode(),
		authority,
	)
	.map_err(|cause| CheckedCopyError::Journal(FrameKind::DurabilityRecorded, cause))?;
	if DurabilityRecorded::from_frame(&frame).map_err(CheckedCopyError::Record)? != durable
		|| frame.previous_digest() != observed_frame.head().digest()
		|| observed_frame.head().sequence().checked_add(1) != Some(frame.head().sequence())
	{
		return Err(CheckedCopyError::Binding);
	}
	journal
		.confirm_current_suffix(&durable_frame, &durable_frame, &mut [])
		.map_err(|cause| CheckedCopyError::Journal(FrameKind::DurabilityRecorded, cause))?;
	model_observation(session, model_binding, CopyEvent::DirectoryFlushed)?;
	let plan = request.private_plan;
	let destination = plan.destination();
	let evidence = ReceiptEvidence {
		context: plan.context(),
		entry: plan.attempt().entry,
		source: recorded.verification().source().identity,
		destination: destination.root,
		target: destination.component,
		stream: stage,
	};
	let private_receipt = CopyReceipt::from_synced_durability(evidence, &durable_frame)
		.map_err(CheckedCopyError::Receipt)?;
	let receipt = PublicApplyReceipt::new(
		private_receipt,
		owner,
		intent_frame.head(),
		selection.qualification.record,
	)
	.map_err(CheckedCopyError::PublicReceipt)?;
	let exact = receipt.encode();
	let held = job
		.seal_fresh_receipt_admitted(&exact, authority)
		.map_err(CheckedCopyError::ReceiptSeal)?;
	let receipt_hold = ReceiptHold { held, exact };
	let bytes = receipt_hold.read()?;
	let observed_bytes = &bytes[..receipt_hold.exact.len()];
	let readback =
		PublicApplyReceipt::decode(observed_bytes).map_err(CheckedCopyError::PublicReceipt)?;
	if !readback.matches_intent(intent_frame.head(), &intent)
		|| readback.private().evidence() != evidence
		|| readback.private().durability_frame() != durable_frame.head()
	{
		return Err(CheckedCopyError::Binding);
	}
	let committed = ReceiptCommitted::new(context, readback.digest(), durable_frame.head())
		.map_err(CheckedCopyError::Record)?;
	let (_, terminal) = append(
		journal,
		FrameKind::ReceiptCommitted,
		ApplyRecord::ReceiptCommit,
		committed.encode(),
		authority,
	)
	.map_err(|cause| CheckedCopyError::Journal(FrameKind::ReceiptCommitted, cause))?;
	let mut suffix = [0; MAX_SUFFIX_BYTES];
	let length = journal
		.confirm_current_suffix(&seal_frame, &terminal, &mut suffix)
		.map_err(|cause| CheckedCopyError::Journal(FrameKind::ReceiptCommitted, cause))?;
	PublicApplyReceipt::validate_commit(
		&suffix[..length],
		observed_bytes,
		PublicApplyCommitSelection {
			seal: seal_frame.head(),
			association: owner,
			qualification: selection.qualification,
			copy: evidence,
			metadata: recorded.seal.metadata.metadata,
			stage_directory: stage_dir_identity,
			owner_created: request.profile.created,
			expires_at: request.binding.expires_at,
		},
	)
	.map_err(CheckedCopyError::Commit)?;
	Ok(Committed {
		receipt,
		terminal,
		receipt_hold,
	})
}

pub(super) fn model_observation<R, S, P, C, A>(
	session: &mut CopySession,
	binding: CopyBinding,
	event: CopyEvent,
) -> Result<(), CheckedCopyError<R, S, P, C, A>> {
	if session
		.apply(binding, event)
		.map_err(CheckedCopyError::Model)?
		.is_some()
	{
		return Err(CheckedCopyError::Binding);
	}
	Ok(())
}
