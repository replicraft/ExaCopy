//! Read-only inspection of one private Linux copy job.

use ed25519_dalek::VerifyingKey;
use exacopy_content::validate_stream_input;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::{MAX_OWNER_BYTES, OwnerProfileId, OwnerRecord, OwnerStateDirectory};
use exacopy_platform::linux::{DestinationRoot, RecoveryFile, RecoveryInventory, RecoveryJob};

use super::job::native_identity;
use super::{
	JournalBoundary, JournalReplay, JournalTail, LocalCopyPlan, MAX_LOCAL_COPY_PLAN_BYTES,
	replay_journal,
};

mod artifacts;
mod classify;
mod error;
mod finish;

use artifacts::{open_receipt, read_artifact, recheck_receipt, recheck_record};
use classify::classify;
pub use error::{RecoveryInspectError, RecoveryStep};
pub use finish::{RecoveryFinishError, finish_recovery};

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

/// Inspects a local Linux job from a held destination root using independently supplied trust.
///
/// Calls use read-only, same-mount handles to the job, records and current namespace.
/// A shared job lease excludes cooperating copy writers during inspection. Bindings and
/// inode observations are checked again before returning. Other actors can still change
/// the filesystem between observations. Ordinary file reads can advance access times.
///
/// # Errors
/// Rejects unsupported or unauthenticated evidence, unsafe namespace entries, changed
/// observations, and bounded read or decoding failures. An error supplies no basis for mutation.
pub fn inspect_recovery(
	destination: &DestinationRoot,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	scratch: &mut [u8],
) -> Result<RecoveryInspection, RecoveryInspectError> {
	validate_stream_input(0, scratch.len()).map_err(RecoveryInspectError::Input)?;
	let job = destination
		.open_recovery_job(name)
		.map_err(RecoveryStep::Job.platform())?;
	let _lease = job
		.try_read_lease()
		.map_err(RecoveryStep::Lease.platform())?;
	let history = RecoveryHistory::load(&job, name, profile)?;
	let plan = history.plan()?;
	let names = job
		.inventory(plan.attempt().stage_name, plan.destination().component)
		.map_err(RecoveryStep::Namespace.platform())?;
	history.inspect(&job, &names, scratch)
}

struct RecoveryHistory {
	owner_file: RecoveryFile,
	owner: OwnerRecord,
	plan_file: RecoveryFile,
	plan_bytes: Vec<u8>,
	journal_file: RecoveryFile,
	journal: JournalReplay,
	receipt: Option<RecoveryFile>,
}

impl RecoveryHistory {
	fn load(
		job: &RecoveryJob<'_>,
		name: UnixComponent<'_>,
		profile: RecoveryProfile<'_>,
	) -> Result<Self, RecoveryInspectError> {
		let owner_file = job.open_owner().map_err(RecoveryStep::Owner.platform())?;
		let owner = OwnerRecord::decode(
			&read_artifact(&owner_file, RecoveryStep::Owner, MAX_OWNER_BYTES)?,
			profile.id,
			profile.verifying_key,
		)
		.map_err(RecoveryInspectError::Owner)?;
		let manifest = owner.manifest();
		if manifest.state_root != native_identity(job.identity())
			|| manifest.destination_device != job.destination_identity().device()
			|| manifest.directories
				!= [
					OwnerStateDirectory::Journal,
					OwnerStateDirectory::Receipts,
					OwnerStateDirectory::Stage,
				] {
			return Err(RecoveryInspectError::OwnerBinding);
		}

		let plan_file = job.open_plan().map_err(RecoveryStep::Plan.platform())?;
		let plan_bytes = read_artifact(&plan_file, RecoveryStep::Plan, MAX_LOCAL_COPY_PLAN_BYTES)?;
		let plan = LocalCopyPlan::decode(&plan_bytes).map_err(RecoveryInspectError::Plan)?;
		if plan.attempt().job_name != name
			|| plan.destination().root.identity != native_identity(job.destination_identity())
			|| plan.context().plan_digest != manifest.plan_digest
			|| plan.attempt().job != manifest.job
		{
			return Err(RecoveryInspectError::PlanBinding);
		}

		let mut journal_file = job
			.open_first_segment()
			.map_err(RecoveryStep::Journal.platform())?;
		let journal = replay_journal(&mut journal_file, &plan, &owner)
			.map_err(RecoveryInspectError::Journal)?;
		let receipt = open_receipt(job)?;
		if let Some(file) = &receipt {
			artifacts::check_receipt(file, &plan, &journal)?;
		}
		Ok(Self {
			owner_file,
			owner,
			plan_file,
			plan_bytes,
			journal_file,
			journal,
			receipt,
		})
	}

	fn plan(&self) -> Result<LocalCopyPlan<'_>, RecoveryInspectError> {
		LocalCopyPlan::decode(&self.plan_bytes).map_err(RecoveryInspectError::Plan)
	}

	fn inspect(
		&self,
		job: &RecoveryJob<'_>,
		names: &RecoveryInventory<'_>,
		scratch: &mut [u8],
	) -> Result<RecoveryInspection, RecoveryInspectError> {
		let disposition = classify(names, &self.journal, self.receipt.is_some(), scratch)?;
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
