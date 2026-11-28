//! Exact jitter from the real scheduler and correspondence to the widened oracle.

use std::time::Duration;

use crate::connection_retry::equal_jitter;

// Literal ceiling policy through the first two capped retries.
pub(super) const UPPER_MS: [u64; 8] = [1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000];
// Both symbolic row selectors use all three index bits.
const _: () = assert!(UPPER_MS.len() == 8);

pub(super) const NANOS_PER_MILLISECOND: u128 = 1_000_000;

pub(super) fn scaled_jitter_ms(sample: u32, inclusive_width: u64) -> u64 {
	const SAMPLE_SPACE: u64 = 1 << u32::BITS;
	// Every history window is at most 30,001 ms, so the product is below 2^47.
	u64::from(sample) * inclusive_width / SAMPLE_SPACE
}

pub(crate) fn expected_delay_nanos(ceiling_ms: u64, sample: u32) -> u128 {
	let minimum_ms = ceiling_ms / 2;
	let inclusive_width = ceiling_ms - minimum_ms + 1;
	u128::from(minimum_ms + scaled_jitter_ms(sample, inclusive_width)) * NANOS_PER_MILLISECOND
}

#[kani::proof_for_contract(crate::connection_retry::equal_jitter)]
#[kani::unwind(12)]
fn real_equal_jitter_matches_the_exact_delay() {
	let index = usize::from(kani::any::<u8>() & 7);
	let ceiling_ms = UPPER_MS[index];
	let sample = kani::any::<u32>();
	let delay = equal_jitter(ceiling_ms, sample);
	kani::cover!(
		ceiling_ms == 60_000 && sample == 1_u32 << 31 && delay == Duration::from_millis(45_000),
		"real contract returns the exact capped delay for an interior sample"
	);
}

#[kani::proof]
#[kani::solver(minisat)]
#[kani::unwind(12)]
fn narrow_jitter_oracle_matches_widened_formula() {
	const WIDE_SAMPLE_SPACE: u128 = 1 << u32::BITS;
	// Masking a full u8 reaches every row independently of the full u32 sample.
	let row = usize::from(kani::any::<u8>() & 7);
	let ceiling_ms = UPPER_MS[row];
	let sample = kani::any::<u32>();
	let minimum_ms = ceiling_ms / 2;
	let inclusive_width = ceiling_ms - minimum_ms + 1;
	let widened = u128::from(sample) * u128::from(inclusive_width) / WIDE_SAMPLE_SPACE;
	let narrow = u128::from(scaled_jitter_ms(sample, inclusive_width));
	kani::assert(
		narrow == widened,
		"the narrower oracle preserves the exact widened quotient",
	);
	kani::cover!(
		row == 7 && sample == 1 << (u32::BITS - 1) && narrow == 15_000 && widened == 15_000,
		"the second capped row reaches the exact interior quotient"
	);
}
