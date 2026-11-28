use std::time::Duration;

use crate::connection_retry::{FailureSubject, RetryDecision, RetryError, RetrySupervisor};
use crate::kani_checks::jitter_oracle::{NANOS_PER_MILLISECOND, UPPER_MS, expected_delay_nanos};

use super::{OWNER, TICK, start, wait_after};

pub(super) fn check() {
	const EXPECTED_NEXT_GENERATION: u64 = 9;
	let mut supervisor = RetrySupervisor::new(OWNER, Duration::MAX);
	let mut now = Duration::ZERO;
	for (index, ceiling_ms) in UPPER_MS.into_iter().enumerate() {
		let attempt = start(&mut supervisor, now);
		let generation = u64::try_from(index + 1).expect("eight attempts fit in u64");
		kani::assert(
			attempt.generation().get() == generation,
			"each due event allocates the next generation",
		);
		kani::assert(
			supervisor.poll(now) == Err(RetryError::Busy),
			"a claimed attempt excludes another start",
		);
		let sample = kani::any::<u32>();
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
		now = wake_at;
	}
	let due_attempt = start(&mut supervisor, now);
	let generation = due_attempt.generation().get();
	kani::assert(
		generation == EXPECTED_NEXT_GENERATION,
		"the second capped wait still admits the next generation",
	);
	kani::cover!(
		generation == EXPECTED_NEXT_GENERATION,
		"redial after the cap"
	);
}
