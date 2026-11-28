use exacopy_endpoint::linux_apply::{ApplyRecord as Record, ApplyRole as Role, ApplyStep};

use crate::assembly::linux::public_stage::phase_proof::{Inputs, Observation, Phase};

// Independent format and profile maxima at this reviewed revision. The private
// Plan cap is the sum of its maximal canonical fields, including 255-byte names.
// The v2 receipt cap is 259 fixed v1 bytes + 255 name bytes + 180 wrapper bytes.
const OWNER_LIMIT: u64 = 65_536;
const PRIVATE_PLAN_LIMIT: u64 = 1_214;
const PAGE_LIMIT: u64 = 95;
const RECEIPT_LIMIT: u64 = 694;
pub(super) const STAGE_BUFFER_LIMIT: usize = 4_194_304;

pub(super) fn wide_end(offset: u64, count: usize) -> u128 {
	// The dispatcher selects x86-64 Linux, where both source operands fit u64.
	u128::from(offset) + count as u128
}

pub(super) fn next_phase(phase: Phase, step: ApplyStep, extent: u64, buffer: u64) -> Option<Phase> {
	match step {
		ApplyStep::Create(Role::Job) => (phase == Phase::Qualified).then_some(Phase::Bootstrap),
		ApplyStep::Create(role) => permits_create(phase, role).then_some(phase),
		ApplyStep::Sync(role) => permits_sync(phase, role).then_some(phase),
		ApplyStep::Write(role, offset, count) => {
			let limit = write_limit(phase, role, extent)?;
			(count != 0
				&& wide_end(offset, count) <= u128::from(limit)
				&& (role != Role::Stage
					|| count as u128 <= u128::from(buffer.min(STAGE_BUFFER_LIMIT as u64))))
			.then_some(phase)
		}
		ApplyStep::SetStageExtent(length) => {
			(phase == Phase::Copying && length == extent).then_some(phase)
		}
		ApplyStep::SetStagePermissions | ApplyStep::SetStageTimes => {
			(phase == Phase::Copying).then_some(phase)
		}
		ApplyStep::Append(record) => {
			let (from, to) = frame_edge(record);
			(phase == from).then_some(to)
		}
	}
}

fn permits_create(phase: Phase, role: Role) -> bool {
	match role {
		Role::Job | Role::Destination => false,
		Role::Owner | Role::PrivatePlan => phase == Phase::Bootstrap,
		Role::JournalDirectory | Role::FirstSegment => {
			phase == Phase::Bootstrap || phase == Phase::Owner
		}
		Role::StageDirectory | Role::Stage | Role::CheckpointDirectory => phase == Phase::Prepared,
		Role::CheckpointPage(ordinal) => phase == Phase::Copying && valid_page(ordinal),
		Role::ReceiptDirectory | Role::Receipt => phase == Phase::Durable,
	}
}

fn permits_sync(phase: Phase, role: Role) -> bool {
	match role {
		Role::Job => matches!(
			phase,
			Phase::Bootstrap | Phase::Owner | Phase::Prepared | Phase::Durable
		),
		Role::Owner | Role::PrivatePlan => phase == Phase::Bootstrap,
		Role::JournalDirectory | Role::Destination => {
			phase == Phase::Bootstrap || phase == Phase::Owner
		}
		Role::FirstSegment => false,
		Role::StageDirectory | Role::CheckpointDirectory => {
			phase == Phase::Prepared || phase == Phase::Copying
		}
		Role::Stage => phase == Phase::Copying,
		Role::CheckpointPage(ordinal) => phase == Phase::Copying && valid_page(ordinal),
		Role::ReceiptDirectory | Role::Receipt => phase == Phase::Durable,
	}
}

fn write_limit(phase: Phase, role: Role, extent: u64) -> Option<u64> {
	let (required, limit) = match role {
		Role::Owner => (Phase::Bootstrap, OWNER_LIMIT),
		Role::PrivatePlan => (Phase::Bootstrap, PRIVATE_PLAN_LIMIT),
		Role::Stage => (Phase::Copying, extent),
		Role::CheckpointPage(ordinal) if valid_page(ordinal) => (Phase::Copying, PAGE_LIMIT),
		Role::Receipt => (Phase::Durable, RECEIPT_LIMIT),
		_ => return None,
	};
	(phase == required).then_some(limit)
}

fn valid_page(ordinal: u32) -> bool {
	ordinal != 0 && ordinal < 4097
}

fn frame_edge(record: Record) -> (Phase, Phase) {
	match record {
		Record::Prepared => (Phase::Owner, Phase::Prepared),
		Record::Entry => (Phase::Stage, Phase::Copying),
		Record::Range => (Phase::Copying, Phase::Copying),
		Record::Seal => (Phase::Copying, Phase::Sealed),
		Record::Verification => (Phase::Sealed, Phase::Verified),
		Record::Metadata => (Phase::Verified, Phase::Metadata),
		Record::Intent => (Phase::Metadata, Phase::IntentStarted),
		Record::Observation => (Phase::Settled, Phase::Observed),
		Record::Durability => (Phase::Observed, Phase::Durable),
		Record::ReceiptCommit => (Phase::Durable, Phase::CommitStarted),
	}
}

pub(super) fn expected_observation(phase: Phase, inputs: Inputs) -> Observation {
	let has_stage = matches!(
		phase,
		Phase::Stage
			| Phase::Copying
			| Phase::Sealed
			| Phase::Verified
			| Phase::Metadata
			| Phase::IntentStarted
			| Phase::RenameReady
	);
	Observation {
		phase,
		owner: (has_stage || matches!(phase, Phase::Owner | Phase::Prepared))
			.then_some(inputs.owner),
		stage: has_stage.then_some(inputs.stage),
		intent: (phase == Phase::RenameReady).then_some(inputs.intent),
		settlement: (phase == Phase::RenameStarted).then_some(inputs.settlement),
	}
}
