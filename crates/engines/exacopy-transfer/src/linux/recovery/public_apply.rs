use exacopy_content::validate_stream_input;
use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_recovery::{PublicStageJobView, RecoveryInventoryView, RecoveryRecord};
use exacopy_journal::{
	MAX_OWNER_BYTES, OwnerDigest, OwnerStateDirectory, PlanDigest, PublicApplyBinding,
	PublicApplyOwnerRecord,
};

use super::super::replay::{check_public_stage_plan, replay_public_stage};
use super::super::{
	JournalBoundary, JournalReplay, JournalTail, LocalCopyPlan, MAX_LOCAL_COPY_PLAN_BYTES,
};
use super::{
	InspectionError, RecoveryIssue, RecoveryProfile, RecoveryStep, load_range_pages, open_receipt,
	read_artifact, read_checkpoint, recheck_receipt, recheck_record, record_identity, verify,
};

#[cfg(test)]
mod tests;

pub(super) const STAGE_DIRECTORIES: [OwnerStateDirectory; 4] = [
	OwnerStateDirectory::Checkpoints,
	OwnerStateDirectory::Journal,
	OwnerStateDirectory::Receipts,
	OwnerStateDirectory::Stage,
];

/// Read-only observation of a job selected for public-stage inspection.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PublicStageInspection {
	/// The fixed owner name was absent. The job's flavor and approval are unknown.
	OwnerMissing,
	/// An independently selected profile authenticated the public-stage owner.
	Authenticated {
		/// Claims signed together with the private owner.
		evidence: Box<AuthenticatedPublicStage>,
		/// Observed recovery state, without a continuation recommendation.
		history: PublicStageHistory,
	},
}

/// Identity and approved semantics authenticated together by the selected local profile.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AuthenticatedPublicStage {
	/// Digest of the complete signed owner envelope.
	pub owner_digest: OwnerDigest,
	/// Digest of the exact private plan.
	pub private_plan: PlanDigest,
	/// The owner's retained approved public/private association.
	pub binding: PublicApplyBinding,
}

/// Observed availability of the authenticated public stage's preparation history.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PublicStageHistory {
	/// The fixed plan name was absent. The cause of that absence is unknown.
	PlanMissing,
	/// The fixed segment was absent. The cause of that absence is unknown.
	JournalMissing,
	/// A bounded stage-only journal prefix was read.
	Journal {
		/// The last complete accepted frame.
		boundary: JournalBoundary,
		/// Clean EOF or an incomplete trailing frame.
		tail: JournalTail,
		/// Current stage and target observations.
		observation: PublicStageObservation,
	},
}

/// Point-in-time stage evidence that carries no write, cleanup, or publication authority.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PublicStageObservation {
	/// The segment is empty and no stage or target was observed.
	EmptyJournal,
	/// Job preparation was recorded and no stage or target was observed.
	RetainedPreparation,
	/// The recorded stage is present and its private history lacks a complete seal.
	RetainedPartialStage,
	/// The private stage matches the complete seal, approved stream, and checked metadata.
	RetainedVerifiedStage,
	/// An object is present at the selected public name without a supported intent.
	UnexpectedTarget,
	/// A receipt is present although this job flavor stops before intent.
	UnexpectedReceipt,
	/// Available evidence is insufficient for a stronger conclusion.
	RequiresReconciliation(RecoveryIssue),
}

type InspectionResult<J, T> = Result<
	T,
	InspectionError<
		<J as super::RecoveryJobView>::ReadError,
		<J as super::RecoveryJobView>::NamespaceError,
	>,
>;

/// Authenticates and inspects a stage-only public apply job under a retained read lease.
///
/// Expiry is historical evidence here. The function never resumes, retries, or
/// assists a publication. Complete intent or recovery records are unsupported.
///
/// # Errors
/// Refuses malformed, untrusted, changing or inconsistent evidence and unsafe
/// namespace observations. An open error is distinct from observed absence.
pub fn inspect_public_stage_with_job<J: PublicStageJobView>(
	job: &J,
	name: UnixComponent<'_>,
	profile: RecoveryProfile<'_>,
	scratch: &mut [u8],
) -> InspectionResult<J, PublicStageInspection> {
	validate_stream_input(0, scratch.len()).map_err(InspectionError::Input)?;
	let Some(owner_file) = job
		.open_optional_owner()
		.map_err(RecoveryStep::Owner.platform())?
	else {
		return Ok(PublicStageInspection::OwnerMissing);
	};
	let owner = PublicApplyOwnerRecord::decode(
		&read_artifact(&owner_file, RecoveryStep::Owner, MAX_OWNER_BYTES)?,
		profile.id,
		profile.verifying_key,
	)
	.map_err(InspectionError::Owner)?;
	let manifest = owner.manifest();
	let (job_identity, destination) = job.identities();
	if manifest.owner.state_root != record_identity(job_identity)
		|| manifest.owner.destination_device != destination.device
		|| manifest.owner.directories != STAGE_DIRECTORIES
	{
		return Err(InspectionError::OwnerBinding);
	}
	let history = inspect_history(job, name, &owner, record_identity(destination), scratch)?;
	recheck_record(&owner_file, job.open_owner(), RecoveryStep::Owner)?;
	Ok(PublicStageInspection::Authenticated {
		evidence: Box::new(AuthenticatedPublicStage {
			owner_digest: owner.digest(),
			private_plan: manifest.owner.plan_digest,
			binding: manifest.binding,
		}),
		history,
	})
}

fn inspect_history<J: PublicStageJobView>(
	job: &J,
	name: UnixComponent<'_>,
	owner: &PublicApplyOwnerRecord,
	destination: exacopy_journal::LinuxFileIdentity,
	scratch: &mut [u8],
) -> InspectionResult<J, PublicStageHistory> {
	let Some(plan_file) = job
		.open_optional_plan()
		.map_err(RecoveryStep::Plan.platform())?
	else {
		return Ok(PublicStageHistory::PlanMissing);
	};
	let plan_bytes = read_artifact(&plan_file, RecoveryStep::Plan, MAX_LOCAL_COPY_PLAN_BYTES)?;
	let plan = LocalCopyPlan::decode(&plan_bytes).map_err(InspectionError::Plan)?;
	if plan.attempt().job_name != name || plan.destination().root.identity != destination {
		return Err(InspectionError::PlanBinding);
	}
	check_public_stage_plan(&plan, owner).map_err(|_| InspectionError::PlanBinding)?;
	let Some(mut segment) = job
		.open_optional_first_segment()
		.map_err(RecoveryStep::Journal.platform())?
	else {
		recheck_record(&plan_file, job.open_plan(), RecoveryStep::Plan)?;
		return Ok(PublicStageHistory::JournalMissing);
	};
	let journal =
		replay_public_stage(&mut segment, &plan, owner).map_err(InspectionError::Journal)?;
	let _ = load_range_pages(&journal, plan.source().length, |page| {
		read_checkpoint(job, page)
	})?;
	let receipt = open_receipt(job)?;
	let names = job
		.inventory(plan.attempt().stage_name, plan.destination().component)
		.map_err(RecoveryStep::Namespace.platform())?;
	let observation = inspect_namespace(&names, &journal, receipt.is_some(), scratch)?;
	recheck_record(&segment, job.open_first_segment(), RecoveryStep::Journal)?;
	recheck_record(&plan_file, job.open_plan(), RecoveryStep::Plan)?;
	recheck_receipt(job, receipt.as_ref())?;
	names
		.recheck()
		.map_err(RecoveryStep::Namespace.platform())?;
	Ok(PublicStageHistory::Journal {
		boundary: journal.boundary,
		tail: journal.tail,
		observation,
	})
}

fn inspect_namespace<I, E>(
	names: &I,
	journal: &JournalReplay,
	receipt_present: bool,
	scratch: &mut [u8],
) -> Result<
	PublicStageObservation,
	InspectionError<<I::Record as exacopy_endpoint::ReadView>::Error, E>,
>
where
	I: RecoveryInventoryView,
{
	use PublicStageObservation as Outcome;
	if names.target().is_some() {
		return Ok(Outcome::UnexpectedTarget);
	}
	if receipt_present {
		return Ok(Outcome::UnexpectedReceipt);
	}
	if journal.tail != JournalTail::Clean {
		return Ok(Outcome::RequiresReconciliation(RecoveryIssue::TornJournal));
	}
	let Some(stage) = names.stage() else {
		return Ok(if journal.stage.is_some() {
			Outcome::RequiresReconciliation(RecoveryIssue::MissingStageAndTarget)
		} else if journal.boundary.head.sequence() == 0 {
			Outcome::EmptyJournal
		} else {
			Outcome::RetainedPreparation
		});
	};
	if Some(record_identity(stage.identity().into())) != journal.stage {
		return Ok(Outcome::RequiresReconciliation(
			RecoveryIssue::UnrecognizedStage,
		));
	}
	let (Some(verification), Some(metadata)) = (journal.verification, journal.metadata) else {
		return Ok(Outcome::RetainedPartialStage);
	};
	match verify(stage, verification.stage(), Some(metadata), scratch)? {
		Some(issue) => Ok(Outcome::RequiresReconciliation(issue)),
		None => Ok(Outcome::RetainedVerifiedStage),
	}
}
