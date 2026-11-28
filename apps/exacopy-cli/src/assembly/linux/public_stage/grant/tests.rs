use std::panic::catch_unwind;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use exacopy_endpoint::linux_apply::{
	ApplyRecord as Record, ApplyRole as Role, ApplyStep, PublishedFacts,
};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_journal::frame::ChainHead;
use exacopy_journal::{LinuxFileIdentity, OwnerDigest, OwnerTimestamp};

use super::LocalApplyGrantError as Failure;
use super::clock::{ClockSample, GrantClock, QualificationWindow};
use super::effects::{ExpectedSettlement, GrantState};
use super::lock_state;

fn utc(seconds: i64, nanoseconds: u32) -> OwnerTimestamp {
	OwnerTimestamp::new(seconds, nanoseconds).expect("valid test timestamp")
}

fn sample(anchor: Instant, elapsed: u64, utc: OwnerTimestamp) -> ClockSample {
	ClockSample {
		monotonic: anchor + Duration::from_secs(elapsed),
		utc,
	}
}

fn issued(anchor: Instant) -> GrantState {
	let clock = GrantClock::new(
		sample(anchor, 0, utc(100, 500)),
		Duration::from_secs(20),
		utc(100, 0),
		utc(120, 500),
	)
	.expect("valid issuing sample");
	GrantState::new(clock)
}

fn enabled(anchor: Instant, expires_at: OwnerTimestamp) -> GrantState {
	let mut state = issued(anchor);
	state
		.claim(true, Ok(sample(anchor, 1, utc(101, 0))))
		.unwrap();
	state
		.qualify(
			true,
			Ok(sample(anchor, 2, utc(102, 0))),
			QualificationWindow {
				starts_at: utc(102, 0),
				expires_at,
			},
		)
		.unwrap();
	state
}

#[test]
fn scope_refusal_consumes_invocation_and_cannot_be_replaced() {
	let anchor = Instant::now();
	let mut state = issued(anchor);
	assert_eq!(
		state.claim(false, Ok(sample(anchor, 1, utc(101, 0)))),
		Err(Failure::Scope)
	);
	assert_eq!(
		state.claim(true, Ok(sample(anchor, 2, utc(102, 0)))),
		Err(Failure::Spent)
	);
	assert_eq!(
		state.observe(Ok(sample(anchor, 2, utc(102, 0)))),
		Err(Failure::Scope)
	);
}

#[test]
fn exact_clock_edges_reject_independently() {
	let anchor = Instant::now();
	let mut monotonic = enabled(anchor, utc(125, 0));
	assert_eq!(
		monotonic.observe(Ok(sample(anchor, 19, utc(103, 0)))),
		Ok(utc(103, 0))
	);
	assert_eq!(
		monotonic.observe(Ok(sample(anchor, 20, utc(103, 0)))),
		Err(Failure::Expired)
	);

	let mut plan = enabled(anchor, utc(125, 0));
	assert_eq!(
		plan.observe(Ok(sample(anchor, 3, utc(120, 499)))),
		Ok(utc(120, 499))
	);
	assert_eq!(
		plan.observe(Ok(sample(anchor, 4, utc(120, 500)))),
		Err(Failure::Expired)
	);

	let mut qualification = enabled(anchor, utc(105, 5));
	assert_eq!(
		qualification.observe(Ok(sample(anchor, 3, utc(105, 4)))),
		Ok(utc(105, 4))
	);
	assert_eq!(
		qualification.observe(Ok(sample(anchor, 4, utc(105, 5)))),
		Err(Failure::Expired)
	);
}

#[test]
fn verifier_high_water_blocks_effects_even_if_clock_recovers() {
	let anchor = Instant::now();
	let mut state = enabled(anchor, utc(115, 0));
	assert_eq!(
		state.observe(Ok(sample(anchor, 3, utc(111, 1)))),
		Ok(utc(111, 1))
	);
	assert_eq!(
		state.enter(
			ApplyStep::Create(Role::Job),
			9,
			4,
			Ok(sample(anchor, 4, utc(111, 0)))
		),
		Err(Failure::Clock)
	);
	assert_eq!(
		state.enter(
			ApplyStep::Create(Role::Job),
			9,
			4,
			Ok(sample(anchor, 5, utc(112, 0)))
		),
		Err(Failure::Clock)
	);
}

#[test]
fn revocation_and_repeated_qualification_cannot_refresh_authority() {
	let anchor = Instant::now();
	let mut state = issued(anchor);
	state.retire(Failure::Revoked);
	assert_eq!(
		state.claim(true, Ok(sample(anchor, 1, utc(101, 0)))),
		Err(Failure::Revoked)
	);
	assert_eq!(
		state.claim(true, Ok(sample(anchor, 2, utc(102, 0)))),
		Err(Failure::Spent)
	);

	let mut state = enabled(anchor, utc(115, 0));
	assert_eq!(
		state.qualify(
			true,
			Ok(sample(anchor, 3, utc(103, 0))),
			QualificationWindow {
				starts_at: utc(102, 0),
				expires_at: utc(125, 0)
			},
		),
		Err(Failure::Phase)
	);
	assert_eq!(
		state.observe(Ok(sample(anchor, 4, utc(115, 0)))),
		Err(Failure::Expired)
	);
}

fn copy_phase(anchor: Instant) -> (GrantState, ClockSample, OwnerDigest) {
	let mut state = enabled(anchor, utc(115, 0));
	let now = sample(anchor, 3, utc(103, 0));
	let owner = OwnerDigest::from_bytes([1; 32]);
	state
		.enter(ApplyStep::Create(Role::Job), 9, 4, Ok(now))
		.unwrap();
	state.bind_owner(owner, Ok(now)).unwrap();
	state
		.enter(ApplyStep::Append(Record::Prepared), 9, 4, Ok(now))
		.unwrap();
	state
		.bind_stage(true, LinuxFileIdentity::new(1, 2), Ok(now))
		.unwrap();
	state
		.enter(ApplyStep::Append(Record::Entry), 9, 4, Ok(now))
		.unwrap();
	(state, now, owner)
}

#[test]
fn stage_mutation_scope_refuses_wrong_role_and_window() {
	let (mut state, now, _) = copy_phase(Instant::now());
	for step in [
		ApplyStep::Write(Role::Stage, 7, 3),
		ApplyStep::Write(Role::Stage, 0, 5),
		ApplyStep::Write(Role::Stage, u64::MAX, 1),
		ApplyStep::Write(Role::Stage, 0, 0),
		ApplyStep::SetStageExtent(8),
		ApplyStep::Create(Role::CheckpointPage(0)),
		ApplyStep::Create(Role::Receipt),
		ApplyStep::Append(Record::Intent),
		ApplyStep::Sync(Role::Destination),
	] {
		assert_eq!(
			state.enter(step, 9, 4, Ok(now)),
			Err(Failure::Phase),
			"{step:?}"
		);
	}
	assert_eq!(
		state.enter(ApplyStep::Write(Role::Stage, 5, 4), 9, 4, Ok(now)),
		Ok(())
	);
	assert_eq!(
		state.enter(ApplyStep::SetStageExtent(9), 9, 4, Ok(now)),
		Ok(())
	);
}

fn rename_ready(
	anchor: Instant,
) -> (
	GrantState,
	ClockSample,
	OwnerDigest,
	ChainHead,
	ExpectedSettlement,
) {
	let (mut state, now, owner) = copy_phase(anchor);
	let head = ChainHead::after(7, [2; 32]).unwrap();
	let expected = ExpectedSettlement {
		target: JobFileIdentity {
			device: 1,
			inode: 2,
		},
		stage_directory: JobFileIdentity {
			device: 1,
			inode: 3,
		},
		destination: JobFileIdentity {
			device: 1,
			inode: 4,
		},
	};
	for record in [
		Record::Seal,
		Record::Verification,
		Record::Metadata,
		Record::Intent,
	] {
		state
			.enter(ApplyStep::Append(record), 9, 4, Ok(now))
			.unwrap();
	}
	state.bind_intent(true, owner, head, Ok(now)).unwrap();
	(state, now, owner, head, expected)
}

#[test]
fn spent_rename_can_settle_after_revocation_without_closeout_authority() {
	let (mut state, now, owner, head, expected) = rename_ready(Instant::now());
	let foreign_head = ChainHead::after(7, [3; 32]).unwrap();
	assert_eq!(
		state.enter_rename(true, owner, foreign_head, expected, Ok(now)),
		Err(Failure::Scope)
	);
	assert_eq!(
		state.enter_rename(true, owner, head, expected, Ok(now)),
		Ok(())
	);
	assert_eq!(
		state.enter_rename(true, owner, head, expected, Ok(now)),
		Err(Failure::Spent)
	);
	assert_eq!(
		state.enter(ApplyStep::Append(Record::Observation), 9, 4, Ok(now)),
		Err(Failure::Phase)
	);
	let settled = PublishedFacts {
		target: expected.target,
		stage_directory: expected.stage_directory,
		destination: expected.destination,
	};
	let foreign = PublishedFacts {
		stage_directory: JobFileIdentity {
			device: 1,
			inode: 5,
		},
		..settled
	};
	state.retire(Failure::Revoked);
	assert_eq!(state.bind_settled(foreign), Err(Failure::Scope));
	assert_eq!(state.bind_settled(settled), Ok(()));
	assert_eq!(
		state.enter(ApplyStep::Append(Record::Observation), 9, 4, Ok(now)),
		Err(Failure::Revoked)
	);
	assert_eq!(
		state.enter(ApplyStep::Create(Role::Receipt), 9, 4, Ok(now)),
		Err(Failure::Revoked)
	);
}

#[test]
fn a_poisoned_mutex_refuses_all_later_grant_acquisitions() {
	let state = Mutex::new(issued(Instant::now()));
	let poisoned = catch_unwind(|| {
		let _held = state.lock().expect("initially usable mutex");
		panic!("fixture panic while the grant mutex is held");
	});
	assert!(poisoned.is_err());
	assert!(state.is_poisoned());
	assert_eq!(lock_state(&state).err(), Some(Failure::Poisoned));
	assert_eq!(lock_state(&state).err(), Some(Failure::Poisoned));
}

#[test]
fn current_grant_admits_exact_closeout_and_refuses_reuse() {
	let anchor = Instant::now();
	let (mut state, now, owner, head, expected) = rename_ready(anchor);
	state
		.enter_rename(true, owner, head, expected, Ok(now))
		.unwrap();
	state
		.bind_settled(PublishedFacts {
			target: expected.target,
			stage_directory: expected.stage_directory,
			destination: expected.destination,
		})
		.unwrap();

	let trace = [
		ApplyStep::Append(Record::Observation),
		ApplyStep::Append(Record::Durability),
		ApplyStep::Create(Role::ReceiptDirectory),
		ApplyStep::Create(Role::Receipt),
		ApplyStep::Write(Role::Receipt, 0, 16),
		ApplyStep::Sync(Role::Receipt),
		ApplyStep::Sync(Role::ReceiptDirectory),
		ApplyStep::Sync(Role::Job),
		ApplyStep::Append(Record::ReceiptCommit),
	];
	for (elapsed, step) in (4..).zip(trace) {
		let now = sample(anchor, elapsed, utc(104, 0));
		assert_eq!(state.enter(step, 9, 4, Ok(now)), Ok(()), "{step:?}");
	}
	let later = sample(anchor, 13, utc(105, 0));
	assert_eq!(state.claim(true, Ok(later)), Err(Failure::Spent));
	assert_eq!(
		state.enter_rename(true, owner, head, expected, Ok(later)),
		Err(Failure::Spent)
	);
	for step in trace {
		assert_eq!(
			state.enter(step, 9, 4, Ok(later)),
			Err(Failure::Phase),
			"{step:?}"
		);
	}
}
