use super::*;

#[test]
fn signed_claims_cannot_replace_actual_prepared_checkpoint_or_prior_extent() {
	let fixture = Fixture::new();
	for (payload, issue) in [
		(
			include_str!("replay_wrong_prepared.hex"),
			RemoteReplayMismatch::StageBinding,
		),
		(
			include_str!("replay_wrong_coverage.hex"),
			RemoteReplayMismatch::Checkpoint,
		),
		(
			include_str!("replay_wrong_old_extent.hex"),
			RemoteReplayMismatch::Payload(Error::Binding),
		),
	] {
		let bytes = fixture.append(5, FrameKind::RemoteCaptureContinued, &hex(payload));
		fixture.assert_refused(&bytes, 5, issue);
	}
}

#[test]
fn legacy_retirement_before_continuation_selection_still_requires_legacy_qualification() {
	let fixture = Fixture::new();
	let bytes = hex(include_str!(
		"../remote_finalization/retirement_journal.hex"
	));
	let accepted = fixture.replay(bytes.as_slice());
	assert!(matches!(
		accepted.state(),
		RemoteContinuationState::Legacy(_)
	));
	assert_eq!(accepted.attempts().len(), 2);

	let wrong_legacy_selection = RemoteContinuationSelection {
		legacy_qualification: [0x30; 32],
		..fixture.selection()
	};
	let refused =
		replay_remote_continuation(bytes.as_slice(), &fixture.trust(), &wrong_legacy_selection)
			.unwrap();
	assert!(matches!(
		refused.state(),
		RemoteContinuationState::ReconciliationRequired(RemoteReplayIssue::Record {
			kind: FrameKind::RemoteCaptureRetired,
			..
		})
	));
	assert!(refused.boundary().offset < accepted.boundary().offset);
	assert_eq!(refused.attempts().len(), 1);
}
