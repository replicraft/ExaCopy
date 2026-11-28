use std::time::Duration;

use crate::connection_retry::{FailureSubject, RetryDecision, RetryError, RetrySupervisor};
use crate::kani_checks::jitter_oracle::{NANOS_PER_MILLISECOND, UPPER_MS, expected_delay_nanos};

use super::{OWNER, TICK, start, wait_after};

const LOSS_COUNT: usize = UPPER_MS.len();
const BOUNDARY_CEILINGS_MS: [u64; LOSS_COUNT + 1] = [
	1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000, 60_000,
];
const PREFIX_LIMITS: [Duration; LOSS_COUNT + 1] = [
	Duration::ZERO,
	Duration::from_secs(1),
	Duration::from_secs(3),
	Duration::from_secs(7),
	Duration::from_secs(15),
	Duration::from_secs(31),
	Duration::from_secs(63),
	Duration::from_secs(123),
	Duration::from_secs(183),
];
const EXPECTED_NEXT_GENERATION: u64 = 9;

fn at_history_boundary(supervisor: &RetrySupervisor, now: Duration, row: usize) -> bool {
	if row > LOSS_COUNT || now > PREFIX_LIMITS[row] {
		return false;
	}
	let generation = u64::try_from(row).expect("eight losses fit in u64");
	let (waiting, last_observation) = if row == 0 {
		(None, Duration::ZERO)
	} else {
		let Some(early_poll) = now.checked_sub(TICK) else {
			return false;
		};
		(Some(now), early_poll)
	};
	supervisor.matches_history_boundary(
		OWNER,
		generation,
		BOUNDARY_CEILINGS_MS[row],
		waiting,
		last_observation,
	)
}

pub(super) fn check_inductive_history() {
	let samples: [u32; LOSS_COUNT] = kani::any();
	let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
	let mut now = Duration::ZERO;
	let mut row = 0;
	#[kani::loop_invariant(at_history_boundary(&supervisor, now, row))]
	#[kani::loop_decreases(LOSS_COUNT - row)]
	while row < LOSS_COUNT {
		// Return the actual state and assign the whole loop-carried value so
		// inferred modifies can see the write outside the called methods.
		let (next_supervisor, wake_at) = check_row(supervisor, now, row, samples[row]);
		supervisor = next_supervisor;
		now = wake_at;
		row += 1;
	}
	kani::assert(
		row == LOSS_COUNT,
		"all eight loss rows precede the last start",
	);
	let generation = finish(&mut supervisor, now);
	kani::cover!(
		generation == EXPECTED_NEXT_GENERATION,
		"redial after the cap"
	);
}

pub(super) fn check_concrete_history() {
	let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
	let mut now = Duration::ZERO;
	for row in 0..LOSS_COUNT {
		(supervisor, now) = check_row(supervisor, now, row, kani::any::<u32>());
	}
	let generation = finish(&mut supervisor, now);
	kani::cover!(
		generation == EXPECTED_NEXT_GENERATION,
		"redial after the cap"
	);
}

pub(super) fn check_concrete_cap() {
	let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
	let mut now = Duration::ZERO;
	let mut first_cap = Duration::ZERO;
	for row in 0..LOSS_COUNT {
		(supervisor, now) = check_row(supervisor, now, row, 0);
		if row == 6 {
			first_cap = now;
		}
	}
	let generation = finish(&mut supervisor, now);
	let exact_schedule = first_cap == Duration::from_millis(61_500)
		&& now == Duration::from_millis(91_500)
		&& generation == EXPECTED_NEXT_GENERATION;
	kani::assert(
		exact_schedule,
		"real cap witness observes both exact cumulative wakes",
	);
	kani::cover!(exact_schedule, "real redial through both capped waits");
}

fn check_row(
	mut supervisor: RetrySupervisor,
	now: Duration,
	row: usize,
	sample: u32,
) -> (RetrySupervisor, Duration) {
	let ceiling_ms = UPPER_MS[row];
	let attempt = start(&mut supervisor, now);
	let generation = u64::try_from(row + 1).expect("eight attempts fit in u64");
	kani::assert(
		attempt.generation().get() == generation,
		"each due event allocates the next generation",
	);
	kani::assert(
		supervisor.poll(now) == Err(RetryError::Busy),
		"a claimed attempt excludes another start",
	);
	let wake_at = wait_after(
		&mut supervisor,
		now,
		FailureSubject::Attempt(attempt),
		sample,
	);
	let now_nanos = now.as_nanos();
	let wake_nanos = wake_at.as_nanos();
	let minimum_wake = now_nanos + u128::from(ceiling_ms / 2) * NANOS_PER_MILLISECOND;
	let maximum_wake = now_nanos + u128::from(ceiling_ms) * NANOS_PER_MILLISECOND;
	kani::assert(
		wake_nanos == now_nanos + expected_delay_nanos(ceiling_ms, sample),
		"every sample maps proportionally into the inclusive equal-jitter window",
	);
	kani::assert(
		(minimum_wake..=maximum_wake).contains(&wake_nanos),
		"arbitrary jitter stays within this backoff window",
	);
	kani::assert(
		sample != 0 || wake_nanos == minimum_wake,
		"zero jitter sample reaches the lower endpoint",
	);
	kani::assert(
		sample != u32::MAX || wake_nanos == maximum_wake,
		"maximum jitter sample reaches the upper endpoint",
	);
	kani::assert(
		supervisor.poll(wake_at - TICK) == Ok(RetryDecision::WaitUntil(wake_at)),
		"polling immediately before the wake does not start an attempt",
	);
	(supervisor, wake_at)
}

fn finish(supervisor: &mut RetrySupervisor, now: Duration) -> u64 {
	let due_attempt = start(supervisor, now);
	let generation = due_attempt.generation().get();
	kani::assert(
		generation == EXPECTED_NEXT_GENERATION,
		"the second capped wait still admits the next generation",
	);
	generation
}
