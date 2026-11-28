//! Symbolic checks for the grant clock decision in P-083.

use crate::grant_time::{GrantTimeRefusal, MonotonicObservation, UtcWindow, check_grant_time};

fn normalized_utc() -> (i64, u32) {
	let seconds = kani::any();
	let nanos = kani::any();
	kani::assume(nanos < 1_000_000_000);
	(seconds, nanos)
}

fn symbolic_window() -> UtcWindow {
	UtcWindow {
		starts_at: normalized_utc(),
		expires_at: normalized_utc(),
	}
}

fn wide((seconds, nanos): (i64, u32)) -> i128 {
	i128::from(seconds) * 1_000_000_000 + i128::from(nanos)
}

#[kani::proof]
fn grant_time_matches_wide_nanosecond_specification() {
	use GrantTimeRefusal::{Expired, Regressed};
	use MonotonicObservation as Mono;

	let monotonic = match kani::any::<bool>() {
		true => Mono::Current,
		false if kani::any::<bool>() => Mono::Expired,
		false => Mono::Regressed,
	};
	let current = normalized_utc();
	let previous = normalized_utc();
	let original = symbolic_window();
	let qualified = symbolic_window();
	let has_qualification: bool = kani::any();
	let qualification = has_qualification.then_some(qualified);

	// The wide domain represents every normalized UTC pair, including negative
	// seconds. Use the interval intersection directly rather than tuple comparisons.
	let now = wide(current);
	let high_water = wide(previous);
	let original_start = wide(original.starts_at);
	let original_end = wide(original.expires_at);
	let qualified_start = wide(qualified.starts_at);
	let qualified_end = wide(qualified.expires_at);
	let (start, end) = if has_qualification {
		(
			original_start.max(qualified_start),
			original_end.min(qualified_end),
		)
	} else {
		(original_start, original_end)
	};
	let expected = match monotonic {
		Mono::Regressed => Err(Regressed),
		_ if now < high_water => Err(Regressed),
		Mono::Current if start <= now && now < end => Ok(()),
		_ => Err(Expired),
	};
	let actual = check_grant_time(monotonic, current, previous, original, qualification);
	let unqualified = check_grant_time(monotonic, current, previous, original, None);
	kani::assert(
		actual == expected,
		"grant time matches the independent wide UTC specification",
	);
	kani::assert(
		actual.is_err() || unqualified.is_ok(),
		"qualification cannot widen clock admission",
	);

	let original_valid = original_start <= now && now < original_end;
	let in_order = monotonic == Mono::Current && now >= high_water;
	kani::cover!(
		actual.is_ok() && !has_qualification && current == (i64::MIN, 0),
		"admit minimum signed UTC with no qualification"
	);
	kani::cover!(
		actual.is_ok()
			&& has_qualification
			&& now == high_water
			&& now == original_start
			&& now == qualified_start,
		"both UTC starts and the high-water are inclusive"
	);
	kani::cover!(
		actual == Err(Expired) && in_order && now < original_start && !has_qualification,
		"refuse before original UTC start"
	);
	kani::cover!(
		actual == Err(Expired) && in_order && now == original_end && !has_qualification,
		"refuse at original UTC expiry"
	);
	kani::cover!(
		actual == Err(Expired) && unqualified.is_ok() && has_qualification && now < qualified_start,
		"qualification alone refuses before its UTC start"
	);
	kani::cover!(
		actual == Err(Expired)
			&& unqualified.is_ok()
			&& has_qualification
			&& now == qualified_end
			&& qualified_start < qualified_end,
		"qualification alone refuses at its UTC expiry"
	);
	kani::cover!(
		actual == Err(Regressed)
			&& monotonic == Mono::Expired
			&& current == (-1, 999_999_999)
			&& previous == (0, 0)
			&& original_valid,
		"UTC regression across the epoch outranks monotonic expiry"
	);
	kani::cover!(
		actual == Err(Regressed)
			&& monotonic == Mono::Regressed
			&& now >= high_water
			&& now >= original_end,
		"monotonic regression outranks original UTC expiry"
	);
	kani::cover!(
		actual == Err(Expired)
			&& monotonic == Mono::Expired
			&& now >= high_water
			&& original_valid
			&& !has_qualification,
		"monotonic expiry alone refuses"
	);
	kani::cover!(
		actual.is_ok()
			&& current == (i64::MAX, 999_999_998)
			&& original.expires_at == (i64::MAX, 999_999_999),
		"admit one nanosecond before maximum normalized UTC"
	);
	kani::cover!(
		actual == Err(Expired)
			&& in_order
			&& original_valid
			&& has_qualification
			&& now == qualified_start
			&& qualified_start == qualified_end,
		"empty qualification interval cannot admit its boundary"
	);
	kani::cover!(
		actual == Err(Expired)
			&& in_order
			&& original_valid
			&& has_qualification
			&& qualified_end < now
			&& now < qualified_start,
		"reversed qualification interval admits nothing"
	);
}
