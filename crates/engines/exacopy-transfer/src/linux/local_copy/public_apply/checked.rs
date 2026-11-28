use std::io;

use exacopy_endpoint::JournalSegment;
use exacopy_endpoint::linux_apply::{
	ApplyRecord, ApplyStep, CheckedPublication, ExactSourceRoot, GuardedCopyJob, GuardedJobRoot,
	HeldCheckedPublication, LocalApplyAdmission, NativeRenameFacts, PublishedFacts,
};
use exacopy_endpoint::linux_copy::{
	CopyDestinationView, CopySource, PublishableStageDirectory as _,
};
use exacopy_endpoint::linux_job::JobWorkspace;
use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::{
	DurableJournal, DurableJournalError, LinuxFileIdentity, OwnerDigest, OwnerTimestamp,
	PublicApplyIntent,
};
use exacopy_model::{CopyBinding, CopyEffect, CopyEvent};

use super::super::{check_absent, planning::journal_identity};
use super::proposal::{check_current, check_selection, propose};
use super::{
	PublicApplyIntentObservation, PublicApplyIntentSelection, PublicApplyStageRequest, admit_stage,
};
use crate::linux::{CopyError, PlanningRoots, PublicApplyReceipt};
use crate::linux_staging::check_source;

mod closeout;
mod error;
mod prepare;

pub use error::{CheckedApplyError, CheckedCopyError};

/// A completed checked publication and receipt from one original held invocation.
#[derive(Debug)]
pub struct CheckedApply<'name> {
	/// Exact canonical receipt matching the observed committed receipt artifact.
	pub receipt: PublicApplyReceipt<'name>,
	/// Historical kind-18 boundary confirmed through physical readback and exact EOF.
	pub terminal: ChainHead,
}

/// Exact engine-accepted kind-7 fence for one original held invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckedApplyFence {
	owner: OwnerDigest,
	binding: CopyBinding,
	head: ChainHead,
}

impl CheckedApplyFence {
	/// Original signed owner digest.
	#[must_use]
	pub const fn owner(self) -> OwnerDigest {
		self.owner
	}

	/// Exact model and native attempt binding.
	#[must_use]
	pub const fn binding(self) -> CopyBinding {
		self.binding
	}

	/// Independently reread kind-7 head.
	#[must_use]
	pub const fn head(self) -> ChainHead {
		self.head
	}
}

/// In-process authority supplied by the trusted application for one selected invocation.
/// Implementations must bind actual held capabilities and a current independent local grant.
pub trait CheckedApplyAuthority: LocalApplyAdmission {
	/// Exact loss of trusted evidence, scope, time or approval.
	type Error: std::error::Error + Send + Sync + 'static;

	/// Rechecks the original selected build, held native environment and common grant clock.
	/// # Errors
	/// Refuses any stale or inconsistent evidence or approval.
	fn observe(&self) -> Result<PublicApplyIntentObservation, Self::Error>;

	/// Binds the newly created original owner record to this invocation.
	/// # Errors
	/// Refuses a mismatched invocation or failed transition.
	fn bind_owner(&self, owner: OwnerDigest) -> Result<(), Self::Error>;

	/// Binds the actual stage inode immediately before EntryPrepared.
	/// # Errors
	/// Refuses a mismatched invocation or failed transition.
	fn bind_stage(&self, binding: CopyBinding, stage: LinuxFileIdentity)
	-> Result<(), Self::Error>;

	/// Binds the original physical intent independently accepted at exact EOF.
	/// # Errors
	/// Refuses a mismatched invocation or failed transition.
	fn bind_intent(&self, fence: CheckedApplyFence) -> Result<(), Self::Error>;

	/// Enters the revocation guard immediately before the exact one-shot syscall.
	/// # Errors
	/// Refuses stale or already spent approval and inconsistent physical identity.
	fn enter_rename(
		&self,
		fence: CheckedApplyFence,
		facts: NativeRenameFacts<'_>,
	) -> io::Result<Self::Guard<'_>>;

	/// Records already observed settlement. Does not admit any subsequent mutation.
	/// # Errors
	/// Refuses facts inconsistent with the original spent rename.
	fn bind_settled(&self, facts: PublishedFacts) -> Result<(), Self::Error>;
}

type Cause<'root, S, D, J, A> = CheckedCopyError<
	<S as exacopy_endpoint::linux_copy::CopySourceRoot>::Error,
	<D as CopyDestinationView>::Error,
	<J as exacopy_endpoint::linux_copy::CopyWorkspace>::PublishError,
	<D as GuardedJobRoot<'root>>::CreateError,
	<A as CheckedApplyAuthority>::Error,
>;
type Failure<'root, S, D, J, A> =
	CheckedApplyError<Cause<'root, S, D, J, A>, <J as GuardedCopyJob>::CheckedPublishError>;

/// Executes one approved checked Linux create-new operation under held capabilities.
/// This engine consumes runtime authority and evidence supplied by a trusted application.
/// It retains the original source, verified stage, signed records and appender across
/// intent, one no-replace rename, observed barriers and the terminal receipt.
/// # Errors
/// Refuses stale evidence, lost authority, conflict or uncertainty. Incomplete effects
/// retain their original names and artifacts for reconciliation without retry or cleanup.
pub fn apply_checked_public_plan<'root, 'name, S, D, J, A>(
	roots: PlanningRoots<'root, S, D>,
	request: PublicApplyStageRequest<'_, '_, 'name>,
	selection: PublicApplyIntentSelection,
	authority: &A,
	scratch: &mut [u8],
) -> Result<CheckedApply<'name>, Failure<'root, S, D, J, A>>
where
	S: ExactSourceRoot<Source: CopySource<Identity = J::Identity, Metadata = J::Metadata>>,
	D: CopyDestinationView
		+ GuardedJobRoot<'root, Job = J, Error = <D as CopyDestinationView>::Error>,
	J: GuardedCopyJob + JobWorkspace<Error = <D as CopyDestinationView>::Error>,
	J::Segment: JournalSegment,
	A: CheckedApplyAuthority,
{
	use CheckedApplyError::{IntentUnconfirmed, PreIntent, Published, PublishedCustody, Rename};

	check_selection(&request, selection)
		.map_err(|error| PreIntent(CheckedCopyError::proposal(error)))?;
	let (source, entry, binding) = admit_stage::<S, D, J>(&roots, &request, scratch.len())
		.map_err(|error| PreIntent(error.into()))?;
	let admitted = observe_current(&request, selection, authority, request.profile.created)
		.map_err(PreIntent)?;

	let (job, pins, mut journal) =
		prepare::bootstrap::<D, J, S::Error, A>(roots.destination, &request, authority)
			.map_err(PreIntent)?;
	let stage_dir = job
		.create_stage_admitted(authority)
		.map_err(|error| PreIntent(CopyError::CreateStage(error).into()))?;
	job.sync_job_admitted(authority)
		.map_err(|error| PreIntent(CopyError::CreateStage(error).into()))?;
	let pages = job
		.create_checkpoints_admitted(authority)
		.map_err(|error| PreIntent(CopyError::CreateCheckpoints(error).into()))?;
	job.sync_job_admitted(authority)
		.map_err(|error| PreIntent(CopyError::CreateCheckpoints(error).into()))?;
	let mut records =
		prepare::GuardedRecords::new(&entry, &pages, &mut journal, authority, binding);
	let plan = request.private_plan;
	let staged = crate::linux_staging::stage_verified_with(
		&source,
		&stage_dir,
		crate::linux_staging::StageRequest {
			stage_name: plan.attempt().stage_name,
			target: plan.destination().component,
			binding,
		},
		scratch,
		Some(&mut records),
		&crate::linux_staging::GuardedEffects(authority),
	)
	.map_err(|error| PreIntent(CopyError::Stage(error).into()))?;
	if !super::matches_approved_stream(request.binding, staged.observed_streams()) {
		return Err(PreIntent(CopyError::StalePlan.into()));
	}
	check_source(&source).map_err(|error| PreIntent(CopyError::SourcePolicy(error).into()))?;
	let seal = entry
		.seal_stream(
			journal_identity(staged.identity().into()),
			staged.length(),
			staged.digest(),
		)
		.map_err(|error| PreIntent(CopyError::from(error).into()))?;
	let (seal_frame, recorded) =
		prepare::record_seal(&seal, &mut journal, authority).map_err(PreIntent)?;
	let owner = pins.owner_digest();
	let check_scope = || -> Result<(), Cause<'root, S, D, J, A>> {
		roots
			.source
			.recheck_exact_regular_name(plan.source().component, &source)
			.map_err(CheckedCopyError::Source)?;
		check_source(&source).map_err(CopyError::SourcePolicy)?;
		check_absent(roots.destination, plan.destination().component)?;
		pins.recheck(&job, &request)?;
		Ok(())
	};
	check_scope().map_err(PreIntent)?;
	let intent_time =
		observe_current(&request, selection, authority, admitted).map_err(PreIntent)?;
	journal
		.confirm_current_suffix(&recorded.metadata, &recorded.metadata, &mut [])
		.map_err(|cause| {
			PreIntent(CheckedCopyError::Journal(
				FrameKind::MetadataRecorded,
				cause,
			))
		})?;
	let intent = propose(&request, selection, intent_time, owner, &recorded)
		.map_err(|error| PreIntent(CheckedCopyError::proposal(error)))?;
	let (frame, intent_frame) = match append(
		&mut journal,
		FrameKind::PublishIntent,
		ApplyRecord::Intent,
		intent.encode(),
		authority,
	) {
		Ok(result) => result,
		Err(cause @ DurableJournalError::Admission(_)) => {
			return Err(PreIntent(CheckedCopyError::Journal(
				FrameKind::PublishIntent,
				cause,
			)));
		}
		Err(cause) => {
			return Err(IntentUnconfirmed(CheckedCopyError::Journal(
				FrameKind::PublishIntent,
				cause,
			)));
		}
	};
	let actual = PublicApplyIntent::from_frame(&frame)
		.map_err(|cause| IntentUnconfirmed(CheckedCopyError::Intent(cause)))?;
	if actual != intent || intent_frame.head() != frame.head() {
		return Err(IntentUnconfirmed(CheckedCopyError::Binding));
	}
	journal
		.confirm_current_suffix(&intent_frame, &intent_frame, &mut [])
		.map_err(|cause| {
			IntentUnconfirmed(CheckedCopyError::Journal(FrameKind::PublishIntent, cause))
		})?;
	let fence = CheckedApplyFence {
		owner,
		binding,
		head: intent_frame.head(),
	};
	authority
		.bind_intent(fence)
		.map_err(|cause| IntentUnconfirmed(CheckedCopyError::Authority(cause)))?;
	let (staged, mut session, _) = staged.into_parts();
	let permit = match session
		.apply(binding, CopyEvent::PublishIntentRecorded)
		.map_err(|cause| IntentUnconfirmed(CheckedCopyError::Model(cause)))?
	{
		Some(CopyEffect::PublishNoClobber(permit)) => permit,
		_ => return Err(IntentUnconfirmed(CheckedCopyError::Binding)),
	};
	let preflight = || -> Result<CheckedApplyFence, Cause<'root, S, D, J, A>> {
		check_scope()?;
		observe_current(&request, selection, authority, intent_time)?;
		journal
			.confirm_current_suffix(&intent_frame, &intent_frame, &mut [])
			.map_err(|cause| CheckedCopyError::Journal(FrameKind::PublishIntent, cause))?;
		Ok(fence)
	};
	let held = CheckedPublication::publish_checked(staged, permit, preflight, |fence, facts| {
		authority.enter_rename(fence, facts)
	})
	.map_err(Rename)?;
	let published = held.recheck_published().map_err(PublishedCustody)?;
	let stage_dir_identity = journal_identity(stage_dir.identity());
	if journal_identity(published.target) != recorded.verification().stage().identity
		|| journal_identity(published.stage_directory) != stage_dir_identity
		|| journal_identity(published.destination) != plan.destination().root.identity
	{
		return Err(Published(CheckedCopyError::Binding));
	}
	authority
		.bind_settled(published)
		.map_err(|cause| Published(CheckedCopyError::Authority(cause)))?;
	observe_current(&request, selection, authority, intent_time).map_err(Published)?;
	let finished = closeout::commit(
		&request,
		selection,
		authority,
		&job,
		&mut journal,
		closeout::PublishedAttempt {
			intent,
			intent_frame,
			recorded,
			seal_frame,
			stage_dir_identity,
		},
		(&mut session, binding),
	)
	.map_err(Published)?;
	held.recheck_published().map_err(PublishedCustody)?;
	finished.receipt_hold.read_again().map_err(Published)?;
	pins.recheck(&job, &request).map_err(Published)?;
	journal
		.confirm_current_suffix(&finished.terminal, &finished.terminal, &mut [])
		.map_err(|cause| {
			Published(CheckedCopyError::Journal(
				FrameKind::ReceiptCommitted,
				cause,
			))
		})?;
	closeout::model_observation(&mut session, binding, CopyEvent::ReceiptRecorded)
		.map_err(Published)?;
	Ok(CheckedApply {
		receipt: finished.receipt,
		terminal: finished.terminal.head(),
	})
}

fn observe_current<R, S, P, C, A: CheckedApplyAuthority>(
	request: &PublicApplyStageRequest<'_, '_, '_>,
	selection: PublicApplyIntentSelection,
	authority: &A,
	prior: OwnerTimestamp,
) -> Result<OwnerTimestamp, CheckedCopyError<R, S, P, C, A::Error>> {
	let now = authority.observe().map_err(CheckedCopyError::Authority)?;
	check_current(request, selection, Some(now), prior).map_err(CheckedCopyError::proposal)
}

fn append<S: JournalSegment>(
	journal: &mut DurableJournal<S>,
	kind: FrameKind,
	phase: ApplyRecord,
	payload: impl Into<Vec<u8>>,
	authority: &impl LocalApplyAdmission,
) -> Result<(exacopy_journal::frame::Frame, exacopy_journal::SyncedFrame), DurableJournalError> {
	journal.append_frame_admitted(kind, payload.into(), || {
		authority.enter(ApplyStep::Append(phase))
	})
}
