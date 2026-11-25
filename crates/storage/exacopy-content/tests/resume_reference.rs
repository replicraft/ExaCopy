//! Finite integration test of local reuse and reconstruction for P-017.
//!
//! The streams are stable in-memory bytes and all positioned I/O succeeds.
//! A zero byte can represent a logical read from a hole. Physical sparse
//! extents, source epochs, and publication are outside this test's scope.

use std::cell::RefCell;
use std::convert::Infallible;
use std::ops::Range;

use exacopy_content::{CheckpointCandidate, resume_and_measure_at};

const MAX_LENGTH: usize = 3;
const MAX_SCRATCH_WIDTH: usize = MAX_LENGTH + 1;

#[test]
fn resume_matches_the_byte_exact_reference() {
	for length in 0..=MAX_LENGTH {
		for source in binary_streams(length) {
			for history in binary_streams(length) {
				for stage_length in 0..=length {
					for stage in binary_streams(stage_length) {
						for checkpoints in checkpoint_prefixes(length) {
							let case = ResumeCase {
								source: &source,
								history: &history,
								stage: &stage,
								checkpoints: &checkpoints,
							};
							for scratch_width in 1..=MAX_SCRATCH_WIDTH {
								check_resume(&case, scratch_width);
							}
						}
					}
				}
			}
		}
	}
}

fn binary_streams(length: usize) -> impl Iterator<Item = Vec<u8>> {
	(0..1 << length).map(move |bits| {
		(0..length)
			.map(|index| u8::from(bits & (1 << index) != 0))
			.collect()
	})
}

fn checkpoint_prefixes(length: usize) -> impl Iterator<Item = Vec<Range<usize>>> {
	(0..1 << length).map(move |bits| {
		let ends = (1..=length).filter(|end| bits & (1 << (end - 1)) != 0);
		std::iter::once(0)
			.chain(ends.clone())
			.zip(ends)
			.map(|(start, end)| start..end)
			.collect()
	})
}

#[derive(Debug)]
struct ResumeCase<'a> {
	source: &'a [u8],
	history: &'a [u8],
	stage: &'a [u8],
	checkpoints: &'a [Range<usize>],
}

fn check_resume(case: &ResumeCase<'_>, scratch_width: usize) {
	// Derive the write footprint from literal triples of bytes and range membership.
	let mut reused = [false; MAX_LENGTH];
	for range in case.checkpoints {
		let historical = &case.history[range.clone()];
		if case.stage.get(range.clone()) == Some(historical)
			&& &case.source[range.clone()] == historical
		{
			reused[range.clone()].fill(true);
		}
	}
	let expected_writes: Vec<_> = (0..case.source.len())
		.filter(|&offset| !reused[offset])
		.collect();
	let expected_reused = case.source.len() - expected_writes.len();

	let candidates: Vec<_> = case
		.checkpoints
		.iter()
		.map(|range| CheckpointCandidate {
			offset: range.start as u64,
			length: range.len() as u64,
			digest: *blake3::hash(&case.history[range.clone()]).as_bytes(),
		})
		.collect();
	let stage = RefCell::new(case.stage.to_vec());
	let mut write_offsets = Vec::new();
	let mut scratch = [0; MAX_SCRATCH_WIDTH];
	let result = resume_and_measure_at::<Infallible, Infallible, Infallible>(
		case.source.len() as u64,
		case.stage.len() as u64,
		&mut scratch[..scratch_width],
		&candidates,
		|offset, bytes| {
			let begin = offset as usize;
			bytes.copy_from_slice(&case.source[begin..begin + bytes.len()]);
			Ok(())
		},
		|offset, bytes| {
			let begin = offset as usize;
			let end = begin + bytes.len();
			assert!(end <= case.stage.len(), "{case:?}, scratch {scratch_width}");
			bytes.copy_from_slice(&stage.borrow()[begin..end]);
			Ok(())
		},
		|offset, bytes| {
			assert!(!bytes.is_empty(), "{case:?}, scratch {scratch_width}");
			let begin = offset as usize;
			let end = begin + bytes.len();
			let mut stage = stage.borrow_mut();
			if end > stage.len() {
				stage.resize(end, 0);
			}
			stage[begin..end].copy_from_slice(bytes);
			write_offsets.extend(begin..end);
			Ok(())
		},
	)
	.unwrap_or_else(|error| panic!("{case:?}, scratch {scratch_width}: {error}"));

	assert_eq!(
		write_offsets, expected_writes,
		"{case:?}, scratch {scratch_width}"
	);
	assert_eq!(
		stage.into_inner(),
		case.source,
		"{case:?}, scratch {scratch_width}"
	);
	assert_eq!(
		result.reused_bytes, expected_reused as u64,
		"{case:?}, scratch {scratch_width}"
	);
	assert_eq!(
		result.digest.as_bytes(),
		blake3::hash(case.source).as_bytes(),
		"{case:?}, scratch {scratch_width}"
	);
}
