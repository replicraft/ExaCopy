use std::time::Duration;

use crate::connection_retry::{FailureSubject, RetryDecision, RetryError, RetrySupervisor};
use crate::kani_checks::jitter_oracle::{NANOS_PER_MILLISECOND, UPPER_MS, expected_delay_nanos};
use crate::kani_checks::timing_oracle::{add_millisecond_delay, exact_wake};

use super::{OWNER, TICK, start, wait_after};

const LOSS_COUNT: usize = UPPER_MS.len();
const EXPECTED_NEXT_GENERATION: u64 = 9;

pub(super) fn check_full_history<const USE_DURATION_PARTS: bool>() {
	let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
	let mut now = Duration::ZERO;
	for row in 0..LOSS_COUNT {
		(supervisor, now) =
			check_row::<USE_DURATION_PARTS>(supervisor, now, row, kani::any::<u32>());
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
		(supervisor, now) = check_row::<false>(supervisor, now, row, 0);
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

fn check_row<const USE_DURATION_PARTS: bool>(
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
	if USE_DURATION_PARTS {
		check_window_by_parts(now, wake_at, ceiling_ms, sample);
	} else {
		check_window_by_nanos(now, wake_at, ceiling_ms, sample);
	}
	kani::assert(
		supervisor.poll(wake_at - TICK) == Ok(RetryDecision::WaitUntil(wake_at)),
		"polling immediately before the wake does not start an attempt",
	);
	(supervisor, wake_at)
}

fn check_window_by_parts(now: Duration, wake_at: Duration, ceiling_ms: u64, sample: u32) {
	let minimum_wake = add_millisecond_delay(now, ceiling_ms / 2)
		.expect("the minimum wake fits in the history clock");
	let maximum_wake =
		add_millisecond_delay(now, ceiling_ms).expect("the maximum wake fits in the history clock");
	kani::assert(
		Some(wake_at) == exact_wake(now, ceiling_ms, sample),
		"every sample maps proportionally into the inclusive equal-jitter window",
	);
	kani::assert(
		(minimum_wake..=maximum_wake).contains(&wake_at),
		"arbitrary jitter stays within this backoff window",
	);
	kani::assert(
		sample != 0 || wake_at == minimum_wake,
		"zero jitter sample reaches the lower endpoint",
	);
	kani::assert(
		sample != u32::MAX || wake_at == maximum_wake,
		"maximum jitter sample reaches the upper endpoint",
	);
}

fn check_window_by_nanos(now: Duration, wake_at: Duration, ceiling_ms: u64, sample: u32) {
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
