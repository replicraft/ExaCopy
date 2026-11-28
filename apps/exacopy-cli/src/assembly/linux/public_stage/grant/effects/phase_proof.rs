//! Kani-only construction and observation of the private production phase.

use exacopy_endpoint::linux_apply::ApplyStep;
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_journal::frame::ChainHead;
use exacopy_journal::{LinuxFileIdentity, OwnerDigest};

use super::{ExpectedSettlement, GrantPhase, LocalApplyGrantError, StageFacts, bounded};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
	Issued,
	Claimed,
	Qualified,
	Bootstrap,
	Owner,
	Prepared,
	Stage,
	Copying,
	Sealed,
	Verified,
	Metadata,
	IntentStarted,
	RenameReady,
	RenameStarted,
	Settled,
	Observed,
	Durable,
	CommitStarted,
}

#[derive(Clone, Copy)]
pub(crate) struct Inputs {
	pub(crate) owner: OwnerDigest,
	pub(crate) stage: LinuxFileIdentity,
	pub(crate) intent: ChainHead,
	pub(crate) settlement: [JobFileIdentity; 3],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Observation {
	pub(crate) phase: Phase,
	pub(crate) owner: Option<OwnerDigest>,
	pub(crate) stage: Option<LinuxFileIdentity>,
	pub(crate) intent: Option<ChainHead>,
	pub(crate) settlement: Option<[JobFileIdentity; 3]>,
}

pub(crate) fn observe_admission(
	phase: Phase,
	inputs: Inputs,
	step: ApplyStep,
	extent: u64,
	buffer: u64,
) -> (Observation, Result<Observation, LocalApplyGrantError>) {
	let actual = construct(phase, inputs);
	let before = observe(actual);
	(before, actual.admit(step, extent, buffer).map(observe))
}

pub(crate) fn observe_window(offset: u64, count: usize, maximum: u64) -> bool {
	bounded(offset, count, maximum)
}

fn construct(phase: Phase, inputs: Inputs) -> GrantPhase {
	let stage = StageFacts {
		owner: inputs.owner,
		identity: inputs.stage,
	};
	match phase {
		Phase::Issued => GrantPhase::Issued,
		Phase::Claimed => GrantPhase::Claimed,
		Phase::Qualified => GrantPhase::Qualified,
		Phase::Bootstrap => GrantPhase::Bootstrap,
		Phase::Owner => GrantPhase::Owner(inputs.owner),
		Phase::Prepared => GrantPhase::Prepared(inputs.owner),
		Phase::Stage => GrantPhase::Stage(stage),
		Phase::Copying => GrantPhase::Copying(stage),
		Phase::Sealed => GrantPhase::Sealed(stage),
		Phase::Verified => GrantPhase::Verified(stage),
		Phase::Metadata => GrantPhase::Metadata(stage),
		Phase::IntentStarted => GrantPhase::IntentStarted(stage),
		Phase::RenameReady => GrantPhase::RenameReady(stage, inputs.intent),
		Phase::RenameStarted => {
			let [target, stage_directory, destination] = inputs.settlement;
			GrantPhase::RenameStarted(ExpectedSettlement {
				target,
				stage_directory,
				destination,
			})
		}
		Phase::Settled => GrantPhase::Settled,
		Phase::Observed => GrantPhase::Observed,
		Phase::Durable => GrantPhase::Durable,
		Phase::CommitStarted => GrantPhase::CommitStarted,
	}
}

fn observe(actual: GrantPhase) -> Observation {
	let (phase, owner, stage, intent, settlement) = match actual {
		GrantPhase::Issued => (Phase::Issued, None, None, None, None),
		GrantPhase::Claimed => (Phase::Claimed, None, None, None, None),
		GrantPhase::Qualified => (Phase::Qualified, None, None, None, None),
		GrantPhase::Bootstrap => (Phase::Bootstrap, None, None, None, None),
		GrantPhase::Owner(owner) => (Phase::Owner, Some(owner), None, None, None),
		GrantPhase::Prepared(owner) => (Phase::Prepared, Some(owner), None, None, None),
		GrantPhase::Stage(stage) => owner_and_stage(Phase::Stage, stage, None),
		GrantPhase::Copying(stage) => owner_and_stage(Phase::Copying, stage, None),
		GrantPhase::Sealed(stage) => owner_and_stage(Phase::Sealed, stage, None),
		GrantPhase::Verified(stage) => owner_and_stage(Phase::Verified, stage, None),
		GrantPhase::Metadata(stage) => owner_and_stage(Phase::Metadata, stage, None),
		GrantPhase::IntentStarted(stage) => owner_and_stage(Phase::IntentStarted, stage, None),
		GrantPhase::RenameReady(stage, head) => {
			owner_and_stage(Phase::RenameReady, stage, Some(head))
		}
		GrantPhase::RenameStarted(expected) => (
			Phase::RenameStarted,
			None,
			None,
			None,
			Some([
				expected.target,
				expected.stage_directory,
				expected.destination,
			]),
		),
		GrantPhase::Settled => (Phase::Settled, None, None, None, None),
		GrantPhase::Observed => (Phase::Observed, None, None, None, None),
		GrantPhase::Durable => (Phase::Durable, None, None, None, None),
		GrantPhase::CommitStarted => (Phase::CommitStarted, None, None, None, None),
	};
	Observation {
		phase,
		owner,
		stage,
		intent,
		settlement,
	}
}

type ObservedFields = (
	Phase,
	Option<OwnerDigest>,
	Option<LinuxFileIdentity>,
	Option<ChainHead>,
	Option<[JobFileIdentity; 3]>,
);

fn owner_and_stage(phase: Phase, stage: StageFacts, intent: Option<ChainHead>) -> ObservedFields {
	(phase, Some(stage.owner), Some(stage.identity), intent, None)
}
