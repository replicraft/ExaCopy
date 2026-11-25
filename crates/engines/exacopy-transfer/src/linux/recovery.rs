//! Read-only inspection of one private Linux copy job.

use ed25519_dalek::VerifyingKey;
use exacopy_content::{CheckpointCandidate, validate_stream_input};
use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_recovery::{RecoveryInventoryView, RecoveryJobView, RecoveryRecord};
use exacopy_journal::{MAX_OWNER_BYTES, OwnerProfileId, OwnerRecord, OwnerStateDirectory};

use super::{
	JournalBoundary, JournalReplay, JournalTail, LocalCopyPlan, MAX_COPY_RECEIPT_BYTES,
	MAX_LOCAL_COPY_PLAN_BYTES, replay_journal,
};

mod artifacts;
mod classify;
mod error;
mod finish;
mod lease;
mod observations;
mod public_apply;
mod resume;
mod retry;
mod source;

use artifacts::{check_receipt, load_range_pages};
use classify::classify;
pub use error::{InspectionError, RecoveryStep};
pub use finish::{FinishFailure, finish_with_lease};
pub use lease::{
	FinishReceiptDirectory, LeaseInventory, LeaseReadError, ReceiptLease, RecoveryLease,
	RecoveryStageLease, ResumeStageDirectory,
};
use observations::{
	observe_names, open_receipt, read_artifact, read_checkpoint, recheck_receipt, recheck_record,
	record_identity, verify,
};
pub use public_apply::{
	AuthenticatedPublicStage, PublicStageHistory, PublicStageInspection, PublicStageObservation,
	inspect_public_stage_with_job,
};
pub use resume::resume_with_lease;
pub use retry::{RecoverySource, SourceRecoveryFailure, retry_with_lease};

/// Ownership trust supplied independently of the selected job directory.
#[derive(Debug, Clone, Copy)]
pub struct RecoveryProfile<'profile> {
	/// The trusted owner profile identifier.
	pub id: OwnerProfileId,
	/// The trusted owner profile public key.
	pub verifying_key: &'profile VerifyingKey,
}

/// A bounded interpretation of authenticated history and freshly observed Linux objects.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RecoveryInspection {
	/// Boundary of the accepted journal prefix.
	pub journal: JournalBoundary,
	/// How the journal reader reached the end of the accepted prefix.
	pub tail: JournalTail,
	/// What the accepted prefix and current namespace support.
	pub disposition: RecoveryDisposition,
}

/// A point-in-time result. Every variant reports evidence and carries no effect authority.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RecoveryDisposition {
	/// Preparation was recorded without a publication intent. Preserve any checked stage.
	RetainedPreparation,
	/// A verified stage remains private and the target was absent. A later retry needs
	/// fresh source, writer quiescence, journal, and namespace checks and authorization.
	PossibleRetry,
	/// The verified stage is observed at the target. Completed post-rename barriers
	/// are absent from the accepted journal prefix.
	PublishedNeedsBarriers,
	/// The target and recorded barriers agree. The accepted prefix lacks a committed receipt.
	PublishedNeedsReceipt {
		/// Whether a compatible but uncommitted receipt artifact was observed.
		artifact_present: bool,
	},
	/// The current target stream matches the complete publication and committed receipt history.
	/// This reports the recorded local Linux profile with unconfirmed storage durability.
	Complete,
	/// A different regular file occupies the planned target name. Preserve all objects.
	Conflict,
	/// Available evidence supplies no supported continuation.
	RequiresReconciliation(RecoveryIssue),
}

/// The reason a safely opened job remains unresolved.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RecoveryIssue {
	/// No complete initial journal record binds the job to the accepted history.
	MissingPreparation,
	/// An incomplete journal frame needs separate reconciliation before continuation.
	TornJournal,
	/// A private stage is present without a matching recorded identity.
	UnrecognizedStage,
	/// The expected object is absent from both names.
	MissingStageAndTarget,
	/// The supported exclusive rename cannot establish this pair of names.
	ContradictoryNames,
	/// Required staging directory identity is missing or changed.
	StageDirectoryBinding,
	/// The current names disagree with a recorded publication result.
	ContradictoryOutcome,
	/// A prior attempt has a recorded outcome and may need a new recovery decision.
	RecordedAttempt,
	/// A current file's length or BLAKE3 measurement disagrees with the recorded stream.
	StreamMismatch,
	/// The current file disagrees with the recorded portable mode, ownership,
	/// modification time, or single-link policy.
	MetadataMismatch,
	/// The journal commits a receipt but the bounded private receipt name is absent.
	MissingCommittedReceipt,
}

/// Checks a held job under the caller's retained read or exclusive lease.
///
/// # Errors
/// Refuses unsupported scratch, unsafe observations, and unauthenticated evidence.
pub fn inspect_with_job<J: RecoveryJobView>(
	job: &J,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	scratch: &mut [u8],
) -> Result<RecoveryInspection, InspectionError<J::ReadError, J::NamespaceError>> {
	validate_stream_input(0, scratch.len()).map_err(InspectionError::Input)?;
	let history = RecoveryHistory::load(job, name, profile)?;
	let plan = history.plan()?;
	let names = job
		.inventory(plan.attempt().stage_name, plan.destination().component)
		.map_err(RecoveryStep::Namespace.platform())?;
	history.inspect(job, &names, scratch)
}

struct RecoveryHistory<F> {
	owner_file: F,
	owner: OwnerRecord,
	plan_file: F,
	plan_bytes: Vec<u8>,
	journal_file: F,
	journal: JournalReplay,
	ranges: Vec<CheckpointCandidate>,
	receipt: Option<F>,
}

impl<F: RecoveryRecord> RecoveryHistory<F> {
	fn load<J: RecoveryJobView<Record = F, ReadError = F::Error>>(
		job: &J,
		name: UnixComponent<'_>,
		profile: RecoveryProfile<'_>,
	) -> Result<Self, InspectionError<F::Error, J::NamespaceError>> {
		let owner_file = job.open_owner().map_err(RecoveryStep::Owner.platform())?;
		let owner = OwnerRecord::decode(
			&read_artifact(&owner_file, RecoveryStep::Owner, MAX_OWNER_BYTES)?,
			profile.id,
			profile.verifying_key,
		)
		.map_err(InspectionError::Owner)?;
		let manifest = owner.manifest();
		let original_directories = [
			OwnerStateDirectory::Journal,
			OwnerStateDirectory::Receipts,
			OwnerStateDirectory::Stage,
		];
		let checkpoint_directories = [
			OwnerStateDirectory::Checkpoints,
			OwnerStateDirectory::Journal,
			OwnerStateDirectory::Receipts,
			OwnerStateDirectory::Stage,
		];
		let (job_identity, destination_identity) = job.identities();
		if manifest.state_root != record_identity(job_identity)
			|| manifest.destination_device != destination_identity.device
			|| (manifest.directories != original_directories
				&& manifest.directories != checkpoint_directories)
		{
			return Err(InspectionError::OwnerBinding);
		}

		let plan_file = job.open_plan().map_err(RecoveryStep::Plan.platform())?;
		let plan_bytes = read_artifact(&plan_file, RecoveryStep::Plan, MAX_LOCAL_COPY_PLAN_BYTES)?;
		let plan = LocalCopyPlan::decode(&plan_bytes).map_err(InspectionError::Plan)?;
		if plan.attempt().job_name != name
			|| plan.destination().root.identity != record_identity(destination_identity)
			|| plan.context().plan_digest != manifest.plan_digest
			|| plan.attempt().job != manifest.job
		{
			return Err(InspectionError::PlanBinding);
		}

		let mut journal_file = job
			.open_first_segment()
			.map_err(RecoveryStep::Journal.platform())?;
		let journal =
			replay_journal(&mut journal_file, &plan, &owner).map_err(InspectionError::Journal)?;
		let ranges = load_range_pages(&journal, plan.source().length, |page| {
			read_checkpoint(job, page)
		})?;
		let receipt = open_receipt(job)?;
		if let Some(file) = &receipt {
			let bytes = read_artifact(file, RecoveryStep::Receipt, MAX_COPY_RECEIPT_BYTES)?;
			check_receipt(&bytes, &plan, &journal)?;
		}
		Ok(Self {
			owner_file,
			owner,
			plan_file,
			plan_bytes,
			journal_file,
			journal,
			ranges,
			receipt,
		})
	}

	fn plan<N>(&self) -> Result<LocalCopyPlan<'_>, InspectionError<F::Error, N>> {
		LocalCopyPlan::decode(&self.plan_bytes).map_err(InspectionError::Plan)
	}

	fn inspect<'job, J: RecoveryJobView<Record = F, ReadError = F::Error>>(
		&self,
		job: &'job J,
		names: &J::Inventory<'job>,
		scratch: &mut [u8],
	) -> Result<RecoveryInspection, InspectionError<F::Error, J::NamespaceError>> {
		let disposition = classify(
			observe_names(names),
			&self.journal,
			self.receipt.is_some(),
			|file, stream, metadata| verify(file, stream, metadata, scratch),
		)?;
		recheck_record(&self.owner_file, job.open_owner(), RecoveryStep::Owner)?;
		recheck_record(&self.plan_file, job.open_plan(), RecoveryStep::Plan)?;
		recheck_record(
			&self.journal_file,
			job.open_first_segment(),
			RecoveryStep::Journal,
		)?;
		recheck_receipt(job, self.receipt.as_ref())?;
		names
			.recheck()
			.map_err(RecoveryStep::Namespace.platform())?;
		Ok(RecoveryInspection {
			journal: self.journal.boundary,
			tail: self.journal.tail,
			disposition,
		})
	}
}

/// The typed result of retrying or resuming under supplied lease capabilities.
pub type SourceRecoveryResult<L> = Result<
	RecoveryInspection,
	SourceRecoveryFailure<
		LeaseReadError<L>,
		<L as ReceiptLease>::EffectError,
		<L as RecoveryStageLease>::PublishError,
	>,
>;

fn after_admission<R, S, P>(error: FinishFailure<R, S>) -> SourceRecoveryFailure<R, S, P> {
	match error {
		FinishFailure::Inspection(error) => FinishFailure::Completion(error),
		error => error,
	}
	.into()
}
