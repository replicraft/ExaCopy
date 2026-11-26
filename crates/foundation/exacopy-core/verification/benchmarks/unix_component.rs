//! Fixed-input benchmark for shared Unix filename component validation.
#![forbid(unsafe_code)]

use std::hint;
use std::time::{Duration, Instant};

use exacopy_core::{MAX_UNIX_COMPONENT_BYTES, NameError, UnixComponent};

const CALLS_PER_BATCH: u32 = 100_000;
const WARMUP_BATCHES: usize = 3;
const SAMPLE_BATCHES: usize = 9;

fn main() {
	run();
}

fn run() {
	let maximum = [b'x'; MAX_UNIX_COMPONENT_BYTES];
	let mut terminal_nul = maximum;
	terminal_nul[MAX_UNIX_COMPONENT_BYTES - 1] = 0;

	println!("case\tbytes\tcalls_per_batch\tsamples\tmin_ns\tmedian_ns\tmax_ns");
	measure("short_accepted", b"report.dat", Ok(()));
	measure("max_accepted", &maximum, Ok(()));
	measure("max_terminal_nul", &terminal_nul, Err(NameError::Nul));
}

fn measure(name: &str, input: &[u8], expected: Result<(), NameError>) {
	assert_eq!(
		UnixComponent::new(input).map(|_| ()),
		expected,
		"unexpected validation result for {name}",
	);
	for _ in 0..WARMUP_BATCHES {
		validate_batch(input);
	}

	let mut samples = [Duration::ZERO; SAMPLE_BATCHES];
	for sample in &mut samples {
		let start = Instant::now();
		validate_batch(input);
		*sample = start.elapsed();
	}
	samples.sort_unstable();

	let min = ns_per_call(samples[0]);
	let median = ns_per_call(samples[SAMPLE_BATCHES / 2]);
	let max = ns_per_call(samples[SAMPLE_BATCHES - 1]);
	println!(
		"{name}\t{}\t{CALLS_PER_BATCH}\t{SAMPLE_BATCHES}\t{min:.3}\t{median:.3}\t{max:.3}",
		input.len(),
	);
}

fn validate_batch(input: &[u8]) {
	for _ in 0..CALLS_PER_BATCH {
		let _ = hint::black_box(UnixComponent::new(hint::black_box(input)));
	}
}

fn ns_per_call(elapsed: Duration) -> f64 {
	elapsed.as_secs_f64() * 1_000_000_000.0 / f64::from(CALLS_PER_BATCH)
}
