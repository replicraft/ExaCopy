use exacopy_endpoint::JournalSegment;
use exacopy_endpoint::linux_copy::{
	CopyDestinationView, CopySource, CopySourceRoot, CopyWorkspace,
};
use exacopy_endpoint::linux_job::{JobBootstrapRoot, JobWorkspace};
use exacopy_journal::{
	ApplyCrashProfile, ApplyIntentEvidence, ApplyProcessCrashEnvironment, ApplyQualification,
	ApprovedPublicPlanDigest, DurableJournalError, OwnerDigest, OwnerTimestamp,
	PublicApplyAssociation, PublicApplyIntent, PublicApplyIntentError, PublicationPrimitive,
	PublishIntent, PublishIntentContext, PublishIntentTarget,
};

use crate::copy_planning::linux_baseline_metadata_policy_digest;
use crate::linux_staging::check_source;

use super::super::{CopyCheckpoint, CopyError, PlanningRoots, check_absent, records::RecordedSeal};
use super::{HeldStage, PublicApplyStageRequest, StageFinish, stage_with_seal, timestamp_tuple};

#[cfg(test)]
mod tests;

/// Approval and qualification facts selected independently of the Plan and live observations.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PublicApplyIntentSelection {
	/// Digest the operator approved for this attempt.
	pub approved_plan: ApprovedPublicPlanDigest,
	/// Expected profile, environment and exact independently selected evidence digest.
	pub qualification: ApplyQualification,
}

/// Fresh facts observed by the caller before bootstrap and again at the seal.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PublicApplyIntentObservation {
	/// Current UTC from the caller's clock.
	pub now: OwnerTimestamp,
	/// Native profile whose observation succeeded.
	pub profile: ApplyCrashProfile,
	/// Current process-crash environment from the selected native observation.
	pub environment: ApplyProcessCrashEnvironment,
}

/// A failure to stage the approved content or prepare its public intent proposal.
#[derive(Debug)]
#[non_exhaustive]
pub enum PublicApplyIntentPreparationError<R, S, P> {
	/// Existing private-stage or held-scope check failed.
	Stage(CopyError<R, S, P>),
	/// The selected approval differs from the admitted Plan and original owner binding.
	Approval,
	/// Missing or mismatched qualification selection or live environment.
	Qualification,
	/// Fresh native facts or UTC are unavailable.
	ObservationUnavailable,
	/// Current UTC precedes the previous check or reaches the original Plan expiry.
	Time,
	/// The stage's seal does not bind the approved stream, identities and private attempt.
	SealBinding,
	/// The original appender could not confirm its sealed prefix through exact EOF.
	SealReadback(DurableJournalError),
	/// The existing v2 intent format rejected the proposal.
	Format(PublicApplyIntentError),
}

impl<R, S, P> From<CopyError<R, S, P>> for PublicApplyIntentPreparationError<R, S, P> {
	fn from(error: CopyError<R, S, P>) -> Self {
		Self::Stage(error)
	}
}

type IntentFailure<R, D, J> = PublicApplyIntentPreparationError<
	R,
	<D as CopyDestinationView>::Error,
	<J as CopyWorkspace>::PublishError,
>;

/// Stages approved content and prepares the existing v2 intent from that attempt's seal.
///
/// The caller independently selects the expected qualification before invoking this
/// operation and supplies fresh observations before bootstrap and at the seal. A match
/// records those facts. It rereads the exact sealed prefix from the original appender
/// after the final observation. Qualification and fresh authority for actual publication
/// require separate native checks. This scope requires both roots to match the
/// selected profile's device.
///
/// The result contains historical proposal evidence. Returning it releases the
/// active stage and appender. It carries neither authority to append nor a
/// publication permit. This operation never appends an intent or renames a stage.
///
/// # Errors
/// Refuses approval or inconsistent qualification selection before creating a job.
/// Later refusals retain private stage evidence for inspection.
pub fn stage_public_apply_and_propose_intent<'root, 'name, S, D, J>(
	roots: PlanningRoots<'root, S, D>,
	request: PublicApplyStageRequest<'_, '_, 'name>,
	selection: PublicApplyIntentSelection,
	scratch: &mut [u8],
	checkpoint: fn(CopyCheckpoint),
	mut observe: impl FnMut() -> Option<PublicApplyIntentObservation>,
) -> Result<PublicApplyIntent<'name>, IntentFailure<S::Error, D, J>>
where
	S: CopySourceRoot<Source: CopySource<Identity = J::Identity, Metadata = J::Metadata>>,
	D: CopyDestinationView
		+ JobBootstrapRoot<'root, Job = J, Error = <D as CopyDestinationView>::Error>,
	J: CopyWorkspace + JobWorkspace<Error = <D as CopyDestinationView>::Error>,
	J::Segment: JournalSegment,
{
	check_selection(&request, selection)?;
	let request = &request;
	stage_with_seal(
		roots,
		request,
		scratch,
		checkpoint,
		move || {
			let admitted = check_current(request, selection, observe(), request.profile.created)?;
			Ok((admitted, observe))
		},
		ProposeAtSeal {
			request,
			destination: roots.destination,
			selection,
		},
	)
}

struct ProposeAtSeal<'call, 'request, 'bundle, 'name, 'root, D> {
	request: &'call PublicApplyStageRequest<'request, 'bundle, 'name>,
	destination: &'root D,
	selection: PublicApplyIntentSelection,
}

impl<'name, S, D, J, O>
	StageFinish<S, J, (OwnerTimestamp, O), PublicApplyIntent<'name>, IntentFailure<S::Error, D, J>>
	for ProposeAtSeal<'_, '_, '_, 'name, '_, D>
where
	S: CopySource,
	D: CopyDestinationView,
	J: CopyWorkspace,
	J::Segment: JournalSegment,
	O: FnMut() -> Option<PublicApplyIntentObservation>,
{
	fn finish<'finish, 'stage, 'job>(
		self,
		(admitted, mut observe): (OwnerTimestamp, O),
		source: &S,
		owner: OwnerDigest,
		recorded: RecordedSeal<'_>,
		(_, _, _, _, journal): HeldStage<'finish, 'stage, 'job, J>,
	) -> Result<PublicApplyIntent<'name>, IntentFailure<S::Error, D, J>>
	where
		J: 'job,
		'job: 'stage,
		'stage: 'finish,
	{
		use PublicApplyIntentPreparationError as Error;

		let Self {
			request,
			destination,
			selection,
		} = self;
		check_source(source).map_err(|error| Error::Stage(CopyError::SourcePolicy(error)))?;
		check_absent(destination, request.private_plan.destination().component)
			.map_err(Error::Stage)?;
		let now = check_current(request, selection, observe(), admitted)?;
		recorded
			.confirm_journal(journal)
			.map_err(Error::SealReadback)?;
		propose(request, selection, now, owner, &recorded)
	}
}

fn check_selection<R, S, P>(
	request: &PublicApplyStageRequest<'_, '_, '_>,
	selection: PublicApplyIntentSelection,
) -> Result<(), PublicApplyIntentPreparationError<R, S, P>> {
	use PublicApplyIntentPreparationError as Error;

	if selection.approved_plan != request.binding.public_plan
		|| selection.approved_plan.as_bytes() != &request.approved.body().digest()
	{
		return Err(Error::Approval);
	}
	let qualification = selection.qualification;
	let environment = qualification.environment;
	let plan = request.private_plan;
	if qualification.record.as_bytes() == &[0; 32]
		|| environment.boot_id == [0; 16]
		|| environment.mount_namespace == 0
		|| environment.unique_mount == 0
		|| environment.device != plan.source().root_identity.device()
		|| environment.device != plan.destination().root.identity.device()
	{
		return Err(Error::Qualification);
	}
	Ok(())
}

fn check_current<R, S, P>(
	request: &PublicApplyStageRequest<'_, '_, '_>,
	selection: PublicApplyIntentSelection,
	current: Option<PublicApplyIntentObservation>,
	prior: OwnerTimestamp,
) -> Result<OwnerTimestamp, PublicApplyIntentPreparationError<R, S, P>> {
	use PublicApplyIntentPreparationError as Error;

	let current = current.ok_or(Error::ObservationUnavailable)?;
	if current.profile != selection.qualification.profile
		|| current.environment != selection.qualification.environment
	{
		return Err(Error::Qualification);
	}
	let now = timestamp_tuple(current.now);
	if now < timestamp_tuple(prior)
		|| request
			.binding
			.expires_at
			.is_some_and(|expiry| now >= timestamp_tuple(expiry))
	{
		return Err(Error::Time);
	}
	Ok(current.now)
}

fn propose<'name, R, S, P>(
	request: &PublicApplyStageRequest<'_, '_, 'name>,
	selection: PublicApplyIntentSelection,
	now: OwnerTimestamp,
	owner: OwnerDigest,
	recorded: &RecordedSeal<'_>,
) -> Result<PublicApplyIntent<'name>, PublicApplyIntentPreparationError<R, S, P>> {
	use PublicApplyIntentPreparationError as Error;

	let plan = request.private_plan;
	let context = plan.context();
	let destination = plan.destination();
	let verified = recorded.verification();
	let binding = request.binding;
	if verified.context != context
		|| verified.entry != plan.attempt().entry
		|| verified.source().identity != plan.source().file_identity
		|| verified.source().length != binding.stream_length
		|| verified.stage().length != binding.stream_length
		|| verified.source().digest.as_bytes() != binding.stream_digest.as_bytes()
		|| verified.stage().digest.as_bytes() != binding.stream_digest.as_bytes()
		|| binding.metadata_policy.as_bytes() != &linux_baseline_metadata_policy_digest()
	{
		return Err(Error::SealBinding);
	}
	let (verification, metadata) = recorded.heads();
	let candidate = PublishIntent {
		context: PublishIntentContext {
			job: context.job,
			epoch: context.epoch,
			entry: plan.attempt().entry,
			effect_sequence: 1,
			plan_digest: context.plan_digest,
		},
		target: PublishIntentTarget {
			stage: verified.stage().identity,
			parent: destination.root.identity,
			component: destination.component,
			verification_digest: verified.record_digest(),
			primitive: PublicationPrimitive::LinuxRenameNoReplace,
		},
	};
	PublicApplyIntent::new(
		candidate,
		PublicApplyAssociation {
			owner_digest: owner,
			public_plan: request.binding.public_plan,
			public_entry: request.binding.public_entry,
		},
		ApplyIntentEvidence {
			verification,
			metadata,
			qualification: selection.qualification,
			intent_time: now,
		},
	)
	.map_err(Error::Format)
}
