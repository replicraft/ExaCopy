use exacopy_endpoint::linux_apply::{ApplyRecord, ApplyRole, ApplyStep};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_journal::frame::ChainHead;
use exacopy_journal::{LinuxFileIdentity, OwnerDigest};

use crate::assembly::linux::LocalApplyGrantError;
use crate::assembly::linux::public_stage::phase_proof::{
	Inputs, Phase, observe_admission, observe_window,
};

mod oracle;

use oracle::{STAGE_BUFFER_LIMIT, expected_observation, next_phase, wide_end};

#[kani::proof]
#[kani::unwind(1)]
fn grant_window_matches_full_width_interval() {
	let offset: u64 = kani::any();
	let count: usize = kani::any();
	let limit: u64 = kani::any();
	let end = wide_end(offset, count);
	let actual = observe_window(offset, count, limit);

	kani::assert(
		actual == (count != 0 && end <= u128::from(limit)),
		"grant window matches the independent wide interval",
	);
	kani::cover!(
		actual && end < u128::from(limit),
		"strictly contained grant window"
	);
	kani::cover!(
		actual && end == u128::from(limit),
		"grant window ends on the bound"
	);
	kani::cover!(
		!actual && count == 0 && offset <= limit,
		"zero-length grant window"
	);
	kani::cover!(
		!actual && count != 0 && offset > limit,
		"grant window starts past the bound"
	);
	kani::cover!(
		!actual && offset <= limit && end > u128::from(limit) && end <= u128::from(u64::MAX),
		"representable grant window exceeds the bound"
	);
	kani::cover!(
		!actual && offset <= limit && end > u128::from(u64::MAX),
		"grant window would overflow a native offset"
	);
}

#[kani::proof]
#[kani::unwind(40)]
fn grant_phase_matches_closed_effect_relation() {
	let phase = any_phase();
	let step = any_step();
	let extent: u64 = kani::any();
	let buffer: u64 = kani::any();
	let inputs = any_inputs();
	let (before, actual) = observe_admission(phase, inputs, step, extent, buffer);
	let forecast = next_phase(phase, step, extent, buffer)
		.map(|next| expected_observation(next, inputs))
		.ok_or(LocalApplyGrantError::Phase);
	kani::assert(
		before == expected_observation(phase, inputs),
		"grant phase input observes its exact symbolic payload",
	);
	kani::assert(
		actual == forecast,
		"grant phase and payload match the independent effect relation",
	);
	cover_phase_edges(phase, step, extent, buffer, actual.is_ok());
}

fn choose<T: Copy>(variants: &[T]) -> T {
	// Modulo is onto every listed case. There is no assumption removing a valid variant.
	let index = usize::from(kani::any::<u8>()) % variants.len();
	variants[index]
}

fn any_phase() -> Phase {
	use Phase::{
		Bootstrap, Claimed, CommitStarted, Copying, Durable, IntentStarted, Issued, Metadata,
		Observed, Owner, Prepared, Qualified, RenameReady, RenameStarted, Sealed, Settled, Stage,
		Verified,
	};
	choose(&[
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
	])
}

fn any_step() -> ApplyStep {
	use ApplyRecord as Record;
	use ApplyRole as Role;

	let role = choose(&[
		Role::Job,
		Role::Owner,
		Role::PrivatePlan,
		Role::JournalDirectory,
		Role::FirstSegment,
		Role::StageDirectory,
		Role::Stage,
		Role::CheckpointDirectory,
		Role::CheckpointPage(kani::any()),
		Role::ReceiptDirectory,
		Role::Receipt,
		Role::Destination,
	]);
	let record = choose(&[
		Record::Prepared,
		Record::Entry,
		Record::Range,
		Record::Seal,
		Record::Verification,
		Record::Metadata,
		Record::Intent,
		Record::Observation,
		Record::Durability,
		Record::ReceiptCommit,
	]);
	choose(&[
		ApplyStep::Create(role),
		ApplyStep::Write(role, kani::any(), kani::any()),
		ApplyStep::SetStageExtent(kani::any()),
		ApplyStep::SetStagePermissions,
		ApplyStep::SetStageTimes,
		ApplyStep::Sync(role),
		ApplyStep::Append(record),
	])
}

fn any_inputs() -> Inputs {
	let identity = || JobFileIdentity {
		device: kani::any(),
		inode: kani::any(),
	};
	Inputs {
		owner: OwnerDigest::from_bytes(kani::any()),
		stage: LinuxFileIdentity::new(kani::any(), kani::any()),
		// Map invalid raw encodings to the initial head. All representable heads remain selectable.
		intent: ChainHead::after(kani::any(), kani::any()).unwrap_or_else(ChainHead::start),
		settlement: [identity(), identity(), identity()],
	}
}

fn cover_phase_edges(phase: Phase, step: ApplyStep, extent: u64, buffer: u64, accepted: bool) {
	use ApplyRecord as Record;
	use ApplyRole as Role;
	use ApplyStep::{Append, Create, Write};

	kani::cover!(
		accepted && phase == Phase::Qualified && step == Create(Role::Job),
		"qualified phase admits exclusive job creation"
	);
	let stage = match step {
		Write(Role::Stage, offset, count) => Some((offset, count)),
		_ => None,
	};
	kani::cover!(
		accepted
			&& stage.is_some_and(|(offset, count)| wide_end(offset, count) == u128::from(extent)),
		"stage write at exact approved extent"
	);
	kani::cover!(
		!accepted
			&& phase == Phase::Copying
			&& stage.is_some_and(|(offset, count)| {
				wide_end(offset, count) <= u128::from(extent)
					&& count as u128 <= u128::from(buffer)
					&& count > STAGE_BUFFER_LIMIT
			}),
		"stage write passes plan cap but exceeds content buffer cap"
	);
	kani::cover!(
		!accepted
			&& phase == Phase::Copying
			&& stage.is_some_and(|(offset, count)| {
				wide_end(offset, count) <= u128::from(extent)
					&& count as u128 > u128::from(buffer)
					&& count <= STAGE_BUFFER_LIMIT
			}),
		"stage write passes content cap but exceeds approved buffer cap"
	);
	kani::cover!(
		accepted && step == Create(Role::CheckpointPage(4096)),
		"last valid checkpoint page"
	);
	kani::cover!(
		!accepted && phase == Phase::Copying && step == Create(Role::CheckpointPage(4097)),
		"first invalid upper checkpoint page"
	);
	kani::cover!(
		!accepted && phase == Phase::Copying && step == Create(Role::CheckpointPage(0)),
		"checkpoint zero refused during copying"
	);
	kani::cover!(
		accepted && phase == Phase::Metadata && step == Append(Record::Intent),
		"metadata phase admits the intent record"
	);
	kani::cover!(
		!accepted && phase == Phase::RenameStarted && step == Append(Record::Observation),
		"rename admission alone cannot authorize observation append"
	);
	kani::cover!(
		accepted && phase == Phase::Settled && step == Append(Record::Observation),
		"settled phase admits observation append"
	);
	kani::cover!(
		accepted && phase == Phase::Observed && step == Append(Record::Durability),
		"observed phase admits durability append"
	);
	kani::cover!(
		accepted && phase == Phase::Durable && step == Append(Record::ReceiptCommit),
		"durable phase admits receipt commitment"
	);
	kani::cover!(
		!accepted && phase == Phase::CommitStarted && step == Append(Record::ReceiptCommit),
		"started commitment refuses a further commitment"
	);
}
