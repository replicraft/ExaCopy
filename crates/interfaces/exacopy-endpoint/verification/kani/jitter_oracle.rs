//! Arithmetic correspondence for the transient history's independent oracle.

// Literal ceiling policy through the first two capped retries.
pub(super) const UPPER_MS: [u64; 8] = [1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000];

pub(super) fn scaled_jitter_ms(sample: u32, inclusive_width: u64) -> u64 {
	const SAMPLE_SPACE: u64 = 1 << u32::BITS;
	// Every history window is at most 30,001 ms, so the product is below 2^47.
	u64::from(sample) * inclusive_width / SAMPLE_SPACE
}

#[kani::proof]
#[kani::solver(minisat)]
#[kani::unwind(12)]
fn narrow_jitter_oracle_matches_widened_formula() {
	const WIDE_SAMPLE_SPACE: u128 = 1 << u32::BITS;
	let sample = kani::any::<u32>();
	for ceiling_ms in UPPER_MS {
		let minimum_ms = ceiling_ms / 2;
		let inclusive_width = ceiling_ms - minimum_ms + 1;
		let widened = u128::from(sample) * u128::from(inclusive_width) / WIDE_SAMPLE_SPACE;
		kani::assert(
			u128::from(scaled_jitter_ms(sample, inclusive_width)) == widened,
			"the narrower oracle preserves the exact widened quotient",
		);
	}
	kani::cover!(
		sample == 1 << (u32::BITS - 1),
		"an interior sample reaches the end of all eight window comparisons"
	);
}
