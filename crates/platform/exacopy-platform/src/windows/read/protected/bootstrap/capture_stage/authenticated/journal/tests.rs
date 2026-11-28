use super::*;

struct Guard;

impl WindowsCaptureAdmission for Guard {
	type Guard<'gate> = ();

	fn enter(&self, _: WindowsCaptureEffect) -> io::Result<Self::Guard<'_>> {
		panic!("append-window tests never issue a native guard")
	}
}

#[test]
fn exact_capture_limit_admits_one_final_byte_and_refuses_overflow() {
	let state = AppendState::new();
	let last = MAX_WINDOWS_CAPTURE_SEGMENT_BYTES - 1;
	state.length.set(last);
	state.synced.set(last);
	assert!(state.proposed(last - 1, 1).is_err());
	assert!(state.proposed(last, 0).is_err());
	assert!(state.proposed(last, 2).is_err());
	assert!(state.proposed(last, usize::MAX).is_err());
	let final_byte = state.proposed(last, 1).unwrap();
	assert_eq!(final_byte.start, last);
	assert_eq!(final_byte.end, MAX_WINDOWS_CAPTURE_SEGMENT_BYTES);
	assert!(state.finish(MAX_WINDOWS_CAPTURE_SEGMENT_BYTES).is_err());
}

#[test]
fn dropping_a_partly_written_append_disallows_reuse_or_terminal_success() {
	let state = AppendState::new();
	let first = state.proposed(0, 2).unwrap();
	state.window.set(Some(first));
	state.length.set(1);
	drop(WindowsCaptureJournalGuard::<Guard> {
		state: &state,
		_guard: (),
	});
	assert!(state.window.get().is_none());
	assert!(state.proposed(0, 2).is_err());
	assert!(state.proposed(1, 1).is_err());
	assert!(state.finish(1).is_err());
}

#[test]
fn next_append_starts_at_the_full_synchronized_predecessor() {
	let state = AppendState::new();
	let first = state.proposed(0, 2).unwrap();
	state.window.set(Some(first));
	state.length.set(2);
	state.synced.set(2);
	assert!(state.proposed(2, 1).is_err());
	assert!(state.finish(2).is_err());
	drop(WindowsCaptureJournalGuard::<Guard> {
		state: &state,
		_guard: (),
	});
	state.finish(2).unwrap();
	assert!(state.finish(3).is_err());
	assert!(state.proposed(0, 2).is_err());
	assert_eq!(state.proposed(2, 1).unwrap().end, 3);
}
