use std::time::Duration;

use crate::connection_retry::{FailureSubject, RetryDecision, RetryError, RetrySupervisor};
use crate::kani_checks::jitter_oracle::{UPPER_MS, expected_delay};

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
		let minimum_ms = ceiling_ms / 2;
		let minimum = Duration::from_millis(minimum_ms);
		let maximum = Duration::from_millis(ceiling_ms);
		kani::assert(
			wake_at == now + expected_delay(ceiling_ms, sample),
			"every sample maps proportionally into the inclusive equal-jitter window",
		);
		kani::assert(
			(now + minimum..=now + maximum).contains(&wake_at),
			"arbitrary jitter stays within this backoff window",
		);
		kani::assert(
			sample != 0 || wake_at == now + minimum,
			"zero jitter sample reaches the lower endpoint",
		);
		kani::assert(
			sample != u32::MAX || wake_at == now + maximum,
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
