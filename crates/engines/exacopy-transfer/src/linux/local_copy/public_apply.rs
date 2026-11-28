use exacopy_endpoint::linux_copy::{
	CopyDestinationView, CopySource, CopySourceRoot, CopyWorkspace,
};
use exacopy_endpoint::linux_job::{JobBootstrapRoot, JobWorkspace};
use exacopy_endpoint::linux_staging::{StageWriter, StagingDirectory};
use exacopy_endpoint::{JournalSegment, ReadView as _};
use exacopy_journal::{
	ApplyRequestedDurability, DurableJournal, LinuxFileIdentity, OwnerDigest, OwnerTimestamp,
	PublicApplyBinding,
};
use exacopy_model::{CopyBinding, EntryId, JobId, RunEpoch, StageId};
use exacopy_plan::{PlanDurability, PlanIdentityPlatform, PlanSourceIdentity};

use crate::copy_planning::linux_baseline_metadata_policy_digest;
use crate::linux::job::prepare_public_stage;
use crate::linux_staging::{
	ObservedStreams, StageRequest, VerifiedStage, check_source, stage_verified,
};
use crate::public_plan::AdmittedCopyPlan;

use super::checkpoints::StageRecords;
use super::planning::journal_identity;
use super::records::{EntryEvidence, RecordedSeal};
use super::{
	CopyCheckpoint, CopyError, CopyProfile, LocalCopyPlan, PlanningRoots, preflight_source,
};

mod proposal;
#[cfg(test)]
mod tests;

pub use proposal::{
	PublicApplyIntentObservation, PublicApplyIntentPreparationError, PublicApplyIntentSelection,
	stage_public_apply_and_propose_intent,
};

/// An independently admitted public plan and one private staging attempt.
pub struct PublicApplyStageRequest<'request, 'bundle, 'name> {
	/// The exact approved canonical public Plan with its verified entry page.
	pub approved: &'request AdmittedCopyPlan<'bundle>,
	/// Plan computed against the held roots for this single local attempt.
	pub private_plan: &'request LocalCopyPlan<'name>,
	/// Claims that will be verified against both plans and signed in the durable owner.
	pub binding: PublicApplyBinding,
	/// Independently authorized local signer and recorded admission time.
	pub profile: CopyProfile<'request>,
}

/// Evidence that the job holds a durable public-apply owner and a verified private stage.
///
/// The result exposes no stage handle, journal writer or publication permit.
/// Reopening or reconciling these jobs requires a public-apply-aware workflow.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PublicApplyStage {
	/// Digest of the entire signed owner bound in the preparation journal.
	pub owner_digest: OwnerDigest,
}

type StageFailure<R, D, J> =
	CopyError<R, <D as CopyDestinationView>::Error, <J as CopyWorkspace>::PublishError>;

/// Stages the exact approved bytes and required metadata for a Linux public copy.
///
/// This experimental path writes and synchronizes the mandatory public-apply
/// owner before preparing its journal. It stops before publication intent.
/// Legacy inspection, resume, and retry refuse the new signed owner form.
/// A future apply path requires fresh expiry and the native durability gate.
///
/// # Errors
/// Refuses changed or mismatched plan evidence before bootstrap. Leaves any
/// created private state for reconciliation on a later stream or I/O failure.
pub fn stage_public_apply<'root, S, D, J>(
	roots: PlanningRoots<'root, S, D>,
	request: PublicApplyStageRequest<'_, '_, '_>,
	scratch: &mut [u8],
	checkpoint: fn(CopyCheckpoint),
) -> Result<PublicApplyStage, StageFailure<S::Error, D, J>>
where
	S: CopySourceRoot<Source: CopySource<Identity = J::Identity, Metadata = J::Metadata>>,
	D: CopyDestinationView
		+ JobBootstrapRoot<'root, Job = J, Error = <D as CopyDestinationView>::Error>,
	J: CopyWorkspace + JobWorkspace<Error = <D as CopyDestinationView>::Error>,
	J::Segment: JournalSegment,
{
	stage_with_seal(
		roots,
		&request,
		scratch,
		checkpoint,
		|| Ok(()),
		KeepPrivateStage,
	)
}

type StageDirectory<'job, J> = <J as CopyWorkspace>::Stage<'job>;
type ClosedReader<'stage, D> = <<D as StagingDirectory>::Writer<'stage> as StageWriter>::Reader;
type SealedStage<'stage, 'job, J> = VerifiedStage<ClosedReader<'stage, StageDirectory<'job, J>>>;

// The callback can consume the verified stage at most once. A callback that leaves the slot
// alone keeps the reader and its model session in this coordinator's original drop scope.
type HeldStage<'finish, 'stage, 'job, J> = (
	&'job J,
	&'stage StageDirectory<'job, J>,
	&'finish mut Option<SealedStage<'stage, 'job, J>>,
	CopyBinding,
	&'finish mut DurableJournal<<J as JobWorkspace>::Segment>,
);

// The nested stage borrows must refer to the same actual job and stage lifetimes, including
// inside the invariant Option slot. A generic method ties them at the coordinator call.
trait StageFinish<S, J: CopyWorkspace, A, T, E> {
	fn finish<'finish, 'stage, 'job>(
		self,
		admission: A,
		source: &S,
		owner: OwnerDigest,
		recorded: RecordedSeal<'_>,
		held: HeldStage<'finish, 'stage, 'job, J>,
	) -> Result<T, E>
	where
		J: 'job,
		'job: 'stage,
		'stage: 'finish;
}

struct KeepPrivateStage;

impl<S, J: CopyWorkspace, E> StageFinish<S, J, (), PublicApplyStage, E> for KeepPrivateStage {
	fn finish<'finish, 'stage, 'job>(
		self,
		(): (),
		_source: &S,
		owner_digest: OwnerDigest,
		_recorded: RecordedSeal<'_>,
		_held: HeldStage<'finish, 'stage, 'job, J>,
	) -> Result<PublicApplyStage, E>
	where
		J: 'job,
		'job: 'stage,
		'stage: 'finish,
	{
		Ok(PublicApplyStage { owner_digest })
	}
}

fn stage_with_seal<'root, S, D, J, A, T, E>(
	roots: PlanningRoots<'root, S, D>,
	request: &PublicApplyStageRequest<'_, '_, '_>,
	scratch: &mut [u8],
	checkpoint: fn(CopyCheckpoint),
	before_bootstrap: impl FnOnce() -> Result<A, E>,
	finish: impl StageFinish<S::Source, J, A, T, E>,
) -> Result<T, E>
where
	S: CopySourceRoot<Source: CopySource<Identity = J::Identity, Metadata = J::Metadata>>,
	D: CopyDestinationView
		+ JobBootstrapRoot<'root, Job = J, Error = <D as CopyDestinationView>::Error>,
	J: CopyWorkspace + JobWorkspace<Error = <D as CopyDestinationView>::Error>,
	J::Segment: JournalSegment,
	E: From<StageFailure<S::Error, D, J>>,
{
	let (file, evidence, copy_binding) = admit_stage::<S, D, J>(&roots, request, scratch.len())?;
	let plan = request.private_plan;
	let attempt = plan.attempt();
	let destination = plan.destination();
	let admission = before_bootstrap()?;
	let (job, mut journal, owner_digest) =
		prepare_public_stage(roots.destination, plan, request.profile, request.binding)
			.map_err(CopyError::Bootstrap)?;
	checkpoint(CopyCheckpoint::PlanSynced);
	let directory = job
		.create_stage_directory()
		.map_err(CopyError::CreateStage)?;
	JobWorkspace::sync_directory(&job).map_err(CopyError::CreateStage)?;
	let pages = job
		.create_checkpoint_directory()
		.map_err(CopyError::CreateCheckpoints)?;
	JobWorkspace::sync_directory(&job).map_err(CopyError::CreateCheckpoints)?;

	let mut records = StageRecords::new(&evidence, &pages, &mut journal, checkpoint);
	let stage_directory = &directory;
	let stage = stage_verified(
		&file,
		stage_directory,
		StageRequest {
			stage_name: attempt.stage_name,
			target: destination.component,
			binding: copy_binding,
		},
		scratch,
		Some(&mut records),
	)
	.map_err(CopyError::Stage)?;
	checkpoint(CopyCheckpoint::CopyMetadataApplied);
	if !matches_approved_stream(request.binding, stage.observed_streams()) {
		return Err(CopyError::StalePlan.into());
	}
	check_source(&file).map_err(CopyError::SourcePolicy)?;
	let sealed = evidence
		.seal_stream(
			journal_identity(stage.identity().into()),
			stage.length(),
			stage.digest(),
		)
		.map_err(CopyError::from)?;
	let recorded = sealed
		.record_with_heads(&mut journal)
		.map_err(CopyError::from)?;
	checkpoint(CopyCheckpoint::StageSealed);
	let mut stage = Some(stage);
	finish.finish(
		admission,
		&file,
		owner_digest,
		recorded,
		(
			&job,
			stage_directory,
			&mut stage,
			copy_binding,
			&mut journal,
		),
	)
}

type AdmittedStage<'name, S, D, J> = Result<
	(
		<S as CopySourceRoot>::Source,
		EntryEvidence<'name>,
		CopyBinding,
	),
	StageFailure<<S as CopySourceRoot>::Error, D, J>,
>;

fn admit_stage<'root, 'name, S, D, J>(
	roots: &PlanningRoots<'root, S, D>,
	request: &PublicApplyStageRequest<'_, '_, 'name>,
	scratch_len: usize,
) -> AdmittedStage<'name, S, D, J>
where
	S: CopySourceRoot<Source: CopySource<Identity = J::Identity, Metadata = J::Metadata>>,
	D: CopyDestinationView
		+ JobBootstrapRoot<'root, Job = J, Error = <D as CopyDestinationView>::Error>,
	J: CopyWorkspace + JobWorkspace<Error = <D as CopyDestinationView>::Error>,
	J::Segment: JournalSegment,
{
	if !matches_admitted_binding(request, scratch_len) {
		return Err(CopyError::StalePlan);
	}
	let plan = request.private_plan;
	let file = preflight_source::<S, D, J>(roots, plan, scratch_len)?;
	let context = plan.context();
	let attempt = plan.attempt();
	let copy_binding = CopyBinding::new(
		JobId::try_from_bytes(*context.job.as_bytes()).map_err(|_| CopyError::StalePlan)?,
		EntryId::new(1),
		RunEpoch::new(context.epoch.get()),
		StageId::from_bytes(*attempt.entry.as_bytes()),
	);
	let source = plan.source();
	let destination = plan.destination();
	let evidence = EntryEvidence::new(
		file.copy_observation(),
		source.file_identity,
		file.length(),
		context,
		attempt.entry,
		destination,
	)?;
	Ok((file, evidence, copy_binding))
}

fn matches_admitted_binding(
	request: &PublicApplyStageRequest<'_, '_, '_>,
	scratch_len: usize,
) -> bool {
	let plan = request.private_plan;
	let source = plan.source();
	let destination = plan.destination();
	let attempt = plan.attempt();
	let entry = request.approved.entry();
	let body = request.approved.body();
	let fields = body.fields();
	let binding = request.binding;
	let admitted = timestamp_tuple(request.profile.created);
	let expiry = fields
		.expires_at
		.map(|time| (time.seconds(), time.nanoseconds()));
	binding.public_plan.as_bytes() == &body.digest()
		&& binding.public_entry.as_bytes() == entry.entry_id.as_bytes()
		&& binding.private_entry == attempt.entry
		&& attempt.entry.as_bytes() != &[0; 16]
		&& binding.epoch == attempt.epoch
		&& attempt.epoch.get() != 0
		&& binding.source_root == source.root_id
		&& binding.destination_root == destination.root.id
		&& source.root_id.as_bytes() == entry.source.root_id.as_bytes()
		&& destination.root.id.as_bytes() == entry.destination.root_id.as_bytes()
		&& source.component.as_bytes() == entry.source.basename
		&& destination.component.as_bytes() == entry.destination.basename
		&& entry
			.source_identity
			.is_some_and(|identity| same_native_observation(identity, source.file_identity))
		&& binding.stream_length.get() == entry.stream_length
		&& source.length == entry.stream_length
		&& binding.stream_digest.as_bytes() == &entry.stream_digest
		&& binding.metadata_policy.as_bytes() == &entry.metadata_policy_digest
		&& entry.metadata_policy_digest == linux_baseline_metadata_policy_digest()
		&& binding.expires_at.map(timestamp_tuple) == expiry
		&& (fields.created_at.seconds(), fields.created_at.nanoseconds()) <= admitted
		&& expiry.is_none_or(|expires| admitted < expires)
		&& fields.policy.minimum_durability == PlanDurability::ProcessCrash
		&& binding.requested_durability == ApplyRequestedDurability::ProcessCrash
		&& u64::try_from(scratch_len)
			.is_ok_and(|length| length <= fields.resource_limits.buffer_budget_bytes())
}

fn timestamp_tuple(value: OwnerTimestamp) -> (i64, u32) {
	(value.seconds(), value.nanoseconds())
}

fn same_native_observation(public: PlanSourceIdentity<'_>, private: LinuxFileIdentity) -> bool {
	public.platform == PlanIdentityPlatform::Linux
		&& public.generation.is_none()
		&& public.volume_id == private.device().to_le_bytes()
		&& public.object_id == private.inode().to_le_bytes()
}

fn matches_approved_stream(expected: PublicApplyBinding, observed: ObservedStreams) -> bool {
	let length = expected.stream_length.get();
	let digest = expected.stream_digest.as_bytes();
	observed.source_length == length
		&& observed.source_digest.as_bytes() == digest
		&& observed.stage_length == length
		&& observed.stage_digest.as_bytes() == digest
}
