//! Contracts and symbolic checks for the consumed grant clock decision.

use crate::grant_time::{
	GrantTimeRefusal, MonotonicObservation, UtcWindow, before, check_grant_time,
};

const NANOS_PER_SECOND: i128 = 1_000_000_000;

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

pub(crate) fn wide_utc_before(left: (i64, u32), right: (i64, u32)) -> bool {
	let seconds = i128::from(left.0) - i128::from(right.0);
	let nanos = i128::from(left.1) - i128::from(right.1);
	// For normalized operands, |nanos| is strictly less than one second.
	// Thus clamping a nonzero seconds difference to ±1 preserves the sign of
	// the true wide nanosecond delta, including rollover and signed extremes.
	let seconds_nanos = match seconds.cmp(&0) {
		core::cmp::Ordering::Less => -NANOS_PER_SECOND,
		core::cmp::Ordering::Equal => 0,
		core::cmp::Ordering::Greater => NANOS_PER_SECOND,
	};
	seconds_nanos + nanos < 0
}

#[kani::proof_for_contract(crate::grant_time::before)]
#[kani::unwind(1)]
fn real_utc_before_matches_wide_nanosecond_order() {
	let left = normalized_utc();
	let right = normalized_utc();
	let actual = before(left, right);
	kani::assert(
		actual == wide_utc_before(left, right),
		"the real UTC comparator matches the exact wide delta order",
	);
	kani::cover!(
		actual && left == (-1, 999_999_999) && right == (0, 0),
		"minimum cross-epoch step orders by signed seconds"
	);
	kani::cover!(
		actual && left.0 == right.0 && left.1 < right.1,
		"equal seconds order by subsecond difference"
	);
	kani::cover!(!actual && left == right, "equal UTC does not regress");
	kani::cover!(
		!actual && left == (i64::MAX, 0) && right == (i64::MIN, 999_999_999),
		"full signed seconds difference does not wrap"
	);
}

#[kani::proof]
#[kani::unwind(1)]
#[kani::stub_verified(crate::grant_time::before)]
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

	// Intersect both half-open intervals by conjunction. Neither interval must
	// have positive width, and the optional interval can overlap arbitrarily.
	let utc_regressed = wide_utc_before(current, previous);
	let before_original = wide_utc_before(current, original.starts_at);
	let before_original_end = wide_utc_before(current, original.expires_at);
	let before_qualified = wide_utc_before(current, qualified.starts_at);
	let before_qualified_end = wide_utc_before(current, qualified.expires_at);
	let original_valid = !before_original && before_original_end;
	let qualification_valid = !before_qualified && before_qualified_end;
	let in_order = monotonic == Mono::Current && !utc_regressed;
	let clock_regressed = monotonic == Mono::Regressed || utc_regressed;
	let accepted = in_order && original_valid && (!has_qualification || qualification_valid);
	let expected = match (clock_regressed, accepted) {
		(true, _) => Err(Regressed),
		(false, true) => Ok(()),
		(false, false) => Err(Expired),
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

	kani::cover!(
		actual.is_ok() && !has_qualification && current == (i64::MIN, 0),
		"admit minimum signed UTC with no qualification"
	);
	kani::cover!(
		actual.is_ok()
			&& has_qualification
			&& current == previous
			&& current == original.starts_at
			&& current == qualified.starts_at,
		"both UTC starts and the high-water are inclusive"
	);
	kani::cover!(
		actual == Err(Expired) && in_order && before_original && !has_qualification,
		"refuse before original UTC start"
	);
	kani::cover!(
		actual == Err(Expired) && in_order && current == original.expires_at && !has_qualification,
		"refuse at original UTC expiry"
	);
	kani::cover!(
		actual == Err(Expired) && unqualified.is_ok() && has_qualification && before_qualified,
		"qualification alone refuses before its UTC start"
	);
	kani::cover!(
		actual == Err(Expired)
			&& unqualified.is_ok()
			&& has_qualification
			&& current == qualified.expires_at
			&& wide_utc_before(qualified.starts_at, qualified.expires_at),
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
			&& !utc_regressed
			&& !before_original_end,
		"monotonic regression outranks original UTC expiry"
	);
	kani::cover!(
		actual == Err(Expired)
			&& monotonic == Mono::Expired
			&& !utc_regressed
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
			&& current == qualified.starts_at
			&& qualified.starts_at == qualified.expires_at,
		"empty qualification interval cannot admit its boundary"
	);
	kani::cover!(
		actual == Err(Expired)
			&& in_order
			&& original_valid
			&& has_qualification
			&& wide_utc_before(qualified.expires_at, current)
			&& before_qualified,
		"reversed qualification interval admits nothing"
	);
}
