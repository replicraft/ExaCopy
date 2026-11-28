//! Exact transient timing returned by the production scheduler.

use std::time::Duration;

use crate::connection_retry::retry_timing;

use super::jitter_oracle::{UPPER_MS, expected_delay_nanos, scaled_jitter_ms};

pub(crate) fn timing_matches_wide_bounds(
	now: Duration,
	grant_expires_at: Duration,
	ceiling_ms: u64,
	sample: u32,
	timing: Option<(Duration, u64)>,
) -> bool {
	// The largest legal Duration plus a 60-second delay fits in u128.
	let due_nanos = now.as_nanos() + expected_delay_nanos(ceiling_ms, sample);
	if due_nanos > Duration::MAX.as_nanos() {
		return timing.is_none();
	}
	let Some((wake, next_ceiling)) = timing else {
		return false;
	};
	let Some(expected_ceiling) = expected_next_ceiling(ceiling_ms) else {
		return false;
	};
	wake.subsec_nanos() < 1_000_000_000
		&& wake.as_nanos() == due_nanos.min(grant_expires_at.as_nanos())
		&& next_ceiling == expected_ceiling
}

fn expected_next_ceiling(ceiling_ms: u64) -> Option<u64> {
	Some(match ceiling_ms {
		1_000 => 2_000,
		2_000 => 4_000,
		4_000 => 8_000,
		8_000 => 16_000,
		16_000 => 32_000,
		32_000 | 60_000 => 60_000,
		_ => return None,
	})
}

pub(super) fn add_millisecond_delay(now: Duration, delay_ms: u64) -> Option<Duration> {
	const NANOS_PER_SECOND: u32 = 1_000_000_000;
	const MILLIS_PER_SECOND: u32 = 1_000;
	const NANOS_PER_MILLI: u32 = 1_000_000;

	let delay_ms = u32::try_from(delay_ms).expect("policy delays fit in u32");
	let delay_seconds = u64::from(delay_ms / MILLIS_PER_SECOND);
	let delay_nanos = (delay_ms % MILLIS_PER_SECOND) * NANOS_PER_MILLI;
	let nanos = now.subsec_nanos() + delay_nanos;
	let (carry, subsec_nanos) = if nanos >= NANOS_PER_SECOND {
		(1, nanos - NANOS_PER_SECOND)
	} else {
		(0, nanos)
	};
	let seconds = now
		.as_secs()
		.checked_add(delay_seconds)?
		.checked_add(carry)?;
	Some(Duration::new(seconds, subsec_nanos))
}

pub(super) fn exact_wake(now: Duration, ceiling_ms: u64, sample: u32) -> Option<Duration> {
	let minimum_ms = ceiling_ms / 2;
	let inclusive_width = ceiling_ms - minimum_ms + 1;
	let delay_ms = minimum_ms + scaled_jitter_ms(sample, inclusive_width);
	add_millisecond_delay(now, delay_ms)
}

pub(crate) fn timing_matches_by_parts(
	now: Duration,
	grant_expires_at: Duration,
	ceiling_ms: u64,
	sample: u32,
	timing: Option<(Duration, u64)>,
) -> bool {
	let Some(next) = expected_next_ceiling(ceiling_ms) else {
		return false;
	};
	timing == exact_wake(now, ceiling_ms, sample).map(|due| (due.min(grant_expires_at), next))
}

fn normalized_duration() -> Duration {
	let seconds = kani::any::<u64>();
	let nanos = kani::any::<u32>();
	kani::assume(nanos < 1_000_000_000);
	Duration::new(seconds, nanos)
}

#[kani::proof_for_contract(crate::connection_retry::retry_timing)]
#[kani::unwind(12)]
fn real_retry_timing_matches_wide_wake_and_cap() {
	let now = normalized_duration();
	let expiry = normalized_duration();
	let ceiling_ms = UPPER_MS[usize::from(kani::any::<u8>() & 7)];
	let sample = kani::any::<u32>();
	let actual = retry_timing(now, expiry, ceiling_ms, sample);
	kani::assert(
		timing_matches_wide_bounds(now, expiry, ceiling_ms, sample, actual),
		"real retry timing preserves overflow before lease clipping and the exact cap",
	);
	kani::cover!(
		now == Duration::MAX - Duration::from_nanos(1)
			&& expiry == Duration::MAX
			&& ceiling_ms == 1_000
			&& sample == 0
			&& actual.is_none(),
		"unrepresentable wake refuses while the lease is still live"
	);
	kani::cover!(
		now == Duration::ZERO
			&& expiry == Duration::from_millis(499)
			&& ceiling_ms == 1_000
			&& sample == 0
			&& actual == Some((expiry, 2_000)),
		"representable wake clips to the earlier lease"
	);
	kani::cover!(
		now == Duration::MAX - Duration::from_millis(500)
			&& expiry == Duration::MAX
			&& ceiling_ms == 1_000
			&& sample == 0
			&& actual == Some((Duration::MAX, 2_000)),
		"the exact maximum representable wake is retained"
	);
	kani::cover!(
		now == Duration::ZERO
			&& expiry == Duration::MAX
			&& ceiling_ms == 60_000
			&& sample == u32::MAX
			&& actual == Some((Duration::from_secs(60), 60_000)),
		"a capped ceiling stays capped at the full sample endpoint"
	);
}
