//! Symbolic checks for the range-admission predicate in P-004.

#[kani::proof]
fn checked_range_end_matches_wide_arithmetic() {
	let file_len: u64 = kani::any();
	let start: u64 = kani::any();
	let len: u64 = kani::any();

	// A sum of two u64 values fits in u128, so the oracle does not need the
	// production guard's checked arithmetic or subtraction.
	let wide_end = u128::from(start) + u128::from(len);
	let wide_file_len = u128::from(file_len);
	let expected = (len != 0 && wide_end <= wide_file_len).then_some(wide_end);
	let actual = crate::checked_range_end(file_len, start, len).map(u128::from);

	kani::assert(
		actual == expected,
		"range admission and end match wide arithmetic",
	);
	kani::cover!(
		actual.is_some() && wide_end < wide_file_len,
		"valid interior end"
	);
	kani::cover!(
		actual.is_some() && wide_end == wide_file_len,
		"valid end at EOF"
	);
	kani::cover!(
		actual.is_none() && len == 0 && start <= file_len,
		"empty range"
	);
	kani::cover!(
		actual.is_none() && len != 0 && start > file_len,
		"start beyond EOF"
	);
	kani::cover!(
		actual.is_none()
			&& start <= file_len
			&& wide_end > wide_file_len
			&& wide_end <= u128::from(u64::MAX),
		"representable end beyond EOF"
	);
	kani::cover!(
		actual.is_none() && start <= file_len && wide_end > u128::from(u64::MAX),
		"end exceeds u64"
	);
}
