//! Differential tests for checked range arithmetic.

use proptest::prelude::*;
use proptest::test_runner::{FileFailurePersistence, RngAlgorithm, RngSeed};

use exacopy_model::checked_range_end;

const RANGE_CASES: u32 = 1_024;
const RANGE_SEED: u64 = 0x4558_4143_5241_4E47;

fn range_inputs() -> impl Strategy<Value = (u64, u64, u64)> {
	prop_oneof![
		(any::<u64>(), any::<u64>(), any::<u64>()),
		(any::<u64>(), any::<u64>(), any::<u64>()).prop_map(|(first, second, third)| {
			let mut offsets = [first, second, third];
			offsets.sort_unstable();
			let [start, end, file_len] = offsets;
			(file_len, start, end - start)
		}),
		(any::<u64>(), any::<u64>()).prop_map(|(first, second)| {
			let start = first.min(second);
			let file_len = first.max(second);
			(file_len, start, file_len - start)
		}),
		(1..=u64::MAX, any::<u64>())
			.prop_map(|(start, file_len)| { (file_len, start, u64::MAX - start + 1) }),
	]
}

fn mathematical_range_end(file_len: u64, start: u64, len: u64) -> Option<u64> {
	let start = u128::from(start);
	let end = start + u128::from(len);
	if start < end && end <= u128::from(file_len) {
		u64::try_from(end).ok()
	} else {
		None
	}
}

proptest! {
	#![proptest_config(ProptestConfig {
		cases: RANGE_CASES,
		rng_algorithm: RngAlgorithm::ChaCha,
		rng_seed: RngSeed::Fixed(RANGE_SEED),
		failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("regressions"))),
		..ProptestConfig::default()
	})]

	#[test]
	fn checked_ranges_agree_with_wide_integer_arithmetic((file_len, start, len) in range_inputs()) {
		prop_assert_eq!(checked_range_end(file_len, start, len), mathematical_range_end(file_len, start, len));
	}
}

#[test]
fn half_open_ranges_accept_exact_end_and_reject_empty_or_overflowing_ranges() {
	for (file_len, start, len, expected) in [
		(0, 0, 0, None),
		(0, 0, 1, None),
		(1, 0, 1, Some(1)),
		(1, 1, 0, None),
		(1, 1, 1, None),
		(u64::MAX, 0, u64::MAX, Some(u64::MAX)),
		(u64::MAX, u64::MAX - 1, 1, Some(u64::MAX)),
		(u64::MAX, u64::MAX, 1, None),
		(u64::MAX, 1, u64::MAX, None),
	] {
		assert_eq!(
			checked_range_end(file_len, start, len),
			expected,
			"file length {file_len}, start {start}, length {len}"
		);
	}
}
