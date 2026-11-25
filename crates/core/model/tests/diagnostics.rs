//! Diagnostic behavior for rejected inputs and private stage tokens.

use exacopy_model::{CopyEvent, CopyPhase, InvalidJobId, StageId, TransitionError};

#[test]
fn stage_debug_redacts_the_token() {
	const FIRST_TOKEN: [u8; 16] = [0x51; 16];
	const SECOND_TOKEN: [u8; 16] = [0x57; 16];
	for token in [FIRST_TOKEN, SECOND_TOKEN] {
		let stage = StageId::from_bytes(token);
		assert_eq!(format!("{stage:?}"), "StageId(<redacted>)");
	}
}

#[test]
fn identity_errors_explain_the_binding_and_uuid_requirements() {
	let job_id_error = InvalidJobId.to_string();
	assert!(job_id_error.contains("RFC UUIDv7"), "{job_id_error}");
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
