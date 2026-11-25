//! Diagnostic behavior for rejected model events and bindings.

use exacopy_model::{CopyEvent, CopyPhase, TransitionError};

#[test]
fn mismatched_binding_error_names_the_attempt_conflict() {
	let binding_error = TransitionError::MismatchedBinding.to_string();
	assert!(binding_error.contains("another attempt"), "{binding_error}");
}

#[test]
fn event_order_errors_name_the_phase_and_the_rejected_event() {
	let error = TransitionError::InvalidEvent {
		phase: CopyPhase::Prepared,
		event: CopyEvent::PublishIntentRecorded,
	}
	.to_string();
	assert!(error.contains("Prepared"), "{error}");
	assert!(error.contains("PublishIntentRecorded"), "{error}");
}
