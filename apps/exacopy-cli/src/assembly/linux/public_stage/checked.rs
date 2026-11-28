use std::error::Error;
use std::fmt;
use std::io;

use exacopy_endpoint::linux_apply::{
	ApplyStep, LocalApplyAdmission, NativeRenameFacts, PublishedFacts,
};
use exacopy_journal::{LinuxFileIdentity, OwnerDigest};
use exacopy_model::CopyBinding;
use exacopy_platform::linux::{
	CheckedStageError, JobDirectoryCreationError, PublishError, ReadError, StageError,
};
use exacopy_transfer::linux::{
	CheckedApply, CheckedApplyAuthority, CheckedApplyError, CheckedApplyFence, CheckedCopyError,
	PublicApplyIntentObservation, PublicApplyStageRequest, apply_checked_public_plan,
};

use super::super::CopyRoots;
use super::grant::{LocalApplyEffectGuard, LocalApplyGrant, LocalApplyGrantError};
use super::qualification::{
	QualifiedPublicApplyProposalError, RunningQualification, read_selection,
};

/// Why the actual enrolled host or current local grant refused an apply.
#[derive(Debug)]
#[non_exhaustive]
pub enum LiveQualificationError {
	/// Actual executable, root, record or native profile could not be qualified.
	Qualification(QualifiedPublicApplyProposalError),
	/// The independently selected foreground grant refused.
	Grant(LocalApplyGrantError),
}

impl fmt::Display for LiveQualificationError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Qualification(cause) => fmt::Display::fmt(cause, formatter),
			Self::Grant(cause) => fmt::Display::fmt(cause, formatter),
		}
	}
}

impl Error for LiveQualificationError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Qualification(cause) => Some(cause),
			Self::Grant(cause) => Some(cause),
		}
	}
}

type NativeApplyFailure = CheckedApplyError<
	CheckedCopyError<
		ReadError,
		StageError,
		PublishError,
		JobDirectoryCreationError,
		LiveQualificationError,
	>,
	CheckedStageError,
>;

/// Typed refusal or reconciliation result of a Linux local checked apply attempt.
#[derive(Debug)]
#[non_exhaustive]
pub enum AppliedPublicPlanError {
	/// Admission refused before the engine could create private state.
	Admission(LiveQualificationError),
	/// The exact phase and any native publication or settlement cause.
	Execution(Box<NativeApplyFailure>),
}

impl fmt::Display for AppliedPublicPlanError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Admission(cause) => {
				write!(formatter, "local public apply admission refused: {cause}")
			}
			Self::Execution(cause) => fmt::Display::fmt(cause, formatter),
		}
	}
}

impl Error for AppliedPublicPlanError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Admission(cause) => Some(cause),
			Self::Execution(cause) => Some(cause.as_ref()),
		}
	}
}

/// Applies one approved Linux create-new action under a current qualified local grant.
/// The exact-build enrollment and host policy are independently provisioned. The
/// grant must select the original held roots. This SDK does not install either one.
/// # Errors
/// Refuses unavailable or changed enrollment, scope, time or grant. After intent,
/// may return a conflict, a result requiring reconciliation, or an acknowledged
/// publication with incomplete evidence. No failure removes original artifacts.
pub fn apply_qualified_public_plan<'root, 'name>(
	roots: CopyRoots<'root>,
	request: PublicApplyStageRequest<'_, '_, 'name>,
	grant: &LocalApplyGrant<'_, 'root>,
	scratch: &mut [u8],
) -> Result<CheckedApply<'name>, AppliedPublicPlanError> {
	let apply = prepare_qualified_public_plan(roots, request, grant)?;
	apply(scratch)
}

fn prepare_qualified_public_plan<'root, 'name>(
	roots: CopyRoots<'root>,
	request: PublicApplyStageRequest<'_, '_, 'name>,
	grant: &LocalApplyGrant<'_, 'root>,
) -> Result<
	impl FnOnce(&mut [u8]) -> Result<CheckedApply<'name>, AppliedPublicPlanError>,
	AppliedPublicPlanError,
> {
	use AppliedPublicPlanError::{Admission, Execution};
	use LiveQualificationError::{Grant, Qualification};

	grant
		.claim(roots, &request)
		.map_err(|cause| Admission(Grant(cause)))?;
	let record = read_selection(roots, grant.enrollment(), &request)
		.map_err(|cause| Admission(Qualification(cause)))?;
	let (from, until) = record
		.window()
		.map_err(|cause| Admission(Qualification(cause)))?;
	grant
		.qualify(record.digest, from, until)
		.map_err(|cause| Admission(Grant(cause)))?;
	let running = RunningQualification::open(roots, record)
		.map_err(|cause| Admission(Qualification(cause)))?;
	let selection = running.selection;
	let authority = Authority { grant, running };
	Ok(move |scratch: &mut [u8]| {
		apply_checked_public_plan(roots, request, selection, &authority, scratch)
			.map_err(|cause| Execution(Box::new(cause)))
	})
}

struct Authority<'call, 'policy, 'root> {
	grant: &'call LocalApplyGrant<'policy, 'root>,
	running: RunningQualification<'root>,
}

impl LocalApplyAdmission for Authority<'_, '_, '_> {
	type Guard<'gate>
		= LocalApplyEffectGuard<'gate>
	where
		Self: 'gate;

	fn enter(&self, step: ApplyStep) -> io::Result<Self::Guard<'_>> {
		self.grant.enter(step)
	}
}

impl CheckedApplyAuthority for Authority<'_, '_, '_> {
	type Error = LiveQualificationError;

	fn observe(&self) -> Result<PublicApplyIntentObservation, Self::Error> {
		let environment = self
			.running
			.observe_environment()
			.map_err(LiveQualificationError::Qualification)?;
		let now = self
			.grant
			.recheck_clock()
			.map_err(LiveQualificationError::Grant)?;
		Ok(PublicApplyIntentObservation {
			now,
			profile: self.running.selection.qualification.profile,
			environment,
		})
	}

	fn bind_owner(&self, owner: OwnerDigest) -> Result<(), Self::Error> {
		self.grant
			.bind_owner(owner)
			.map_err(LiveQualificationError::Grant)
	}

	fn bind_stage(
		&self,
		binding: CopyBinding,
		stage: LinuxFileIdentity,
	) -> Result<(), Self::Error> {
		self.grant
			.bind_stage(binding, stage)
			.map_err(LiveQualificationError::Grant)
	}

	fn bind_intent(&self, fence: CheckedApplyFence) -> Result<(), Self::Error> {
		self.grant
			.bind_intent(fence.owner(), fence.binding(), fence.head())
			.map_err(LiveQualificationError::Grant)
	}

	fn enter_rename(
		&self,
		fence: CheckedApplyFence,
		facts: NativeRenameFacts<'_>,
	) -> io::Result<Self::Guard<'_>> {
		self.grant
			.enter_rename(fence.owner(), fence.binding(), fence.head(), facts)
	}

	fn bind_settled(&self, facts: PublishedFacts) -> Result<(), Self::Error> {
		self.grant
			.bind_settled(facts)
			.map_err(LiveQualificationError::Grant)
	}
}
