use super::{CONTENT, CaptureError, Fault, State, capture, capture_live, complete, epoch, fixture};
use crate::remote_capture::MAX_CHECKPOINTS;
use std::num::NonZeroU64;

#[test]
fn refuses_a_pass_that_is_already_from_a_different_epoch() {
	let state = State::default();
	let (mut source, writer, mut records) = fixture(&state, CONTENT, Fault::None);
	let result = complete(capture_live(
		&mut source,
		epoch(2),
		writer,
		&mut records,
		&mut [0; 4],
	));
	assert!(matches!(
		result,
		Err(CaptureError::Epoch { expected, found }) if expected == epoch(2) && found == epoch(1)
	));
	assert!(state.borrow().events.is_empty());
}

#[test]
fn checkpoint_count_is_bounded_and_the_whole_stream_is_still_verified() {
	let state = State::default();
	let content = vec![0xa5; usize::from(MAX_CHECKPOINTS) + 3];
	let (mut source, writer, mut records) = fixture(&state, &content, Fault::None);
	let result = complete(capture(
		&mut source,
		epoch(1),
		writer,
		&mut records,
		&mut [0; 4],
		NonZeroU64::new(1).unwrap(),
	))
	.unwrap();
	let (_, evidence) = result.into_parts();
	assert_eq!(&evidence.source_digest, blake3::hash(&content).as_bytes());
	assert_eq!(evidence.stage_digest.as_bytes(), &evidence.source_digest);
	assert_eq!(state.borrow().ranges.len(), usize::from(MAX_CHECKPOINTS));
}

#[test]
fn rejects_invalid_extent_or_scratch_before_source_reads_or_stage_writes() {
	let state = State::default();
	let (mut source, mut writer, mut records) = fixture(&state, CONTENT, Fault::None);
	writer.length = 9;
	assert!(matches!(
		complete(capture_live(
			&mut source,
			epoch(1),
			writer,
			&mut records,
			&mut [0; 4]
		)),
		Err(CaptureError::Extent {
			expected: 7,
			found: 9
		}),
	));
	let (mut source, writer, mut records) = fixture(&state, CONTENT, Fault::None);
	assert!(matches!(
		complete(capture_live(
			&mut source,
			epoch(1),
			writer,
			&mut records,
			&mut []
		)),
		Err(CaptureError::Input(
			exacopy_content::StreamInputError::EmptyScratch
		)),
	));
	assert!(state.borrow().events.is_empty());
}
