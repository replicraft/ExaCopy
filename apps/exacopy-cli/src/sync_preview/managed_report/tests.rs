use std::num::NonZeroU64;

use exacopy_model::{
	RegularFileEvidence, SyncBlock, SyncConflict, SyncCopyTarget, SyncObservation,
	SyncPathDecision, SyncSide,
};
use exacopy_transfer::linux::sync_preview::FirstSyncPreview;
use serde_json::json;

use super::{render, render_decision};

#[test]
fn reports_policy_limited_live_evidence_and_no_baseline_advance() {
	let file = SyncObservation::Present(RegularFileEvidence {
		byte_len: 17,
		content_digest: [0x12; 32],
		required_metadata_digest: [0x34; 32],
	});
	let (report, code) = render(
		FirstSyncPreview {
			observations: [file, file],
			decision: SyncPathDecision::BaselineMatch,
		},
		[0xab; 16],
		NonZeroU64::MAX,
	);
	assert_eq!(code, 0);
	assert_eq!(
		report,
		json!({
			"status": "matching_observations",
			"left": {
				"state": "present",
				"bytes": 17,
				"stream_digest": "12".repeat(32),
				"required_metadata_digest": "34".repeat(32),
			},
			"right": {
				"state": "present",
				"bytes": 17,
				"stream_digest": "12".repeat(32),
				"required_metadata_digest": "34".repeat(32),
			},
			"selection": {"id": "ab".repeat(16), "revision": "18446744073709551615"},
			"history": "authenticated_p063",
			"scope": "one_subject",
			"scope_complete": true,
			"consistency": "live_observed",
			"comparison": "independent_blake3_unnamed_stream",
			"required_metadata": "linux_owner_and_mode_v1",
			"omitted_metadata": "all_other_metadata",
			"max_file_bytes": super::MAX_PREVIEW_FILE_BYTES,
			"baseline_advanced": false,
		})
	);
}

#[test]
fn renders_each_model_decision_at_its_observation_boundary() {
	use SyncPathDecision::{
		Blocked, BothAbsentAfterCommonPresent, Conflict, CopyCandidate, NoChange,
	};
	use SyncSide::{Left, Right};

	let cases = [
		(NoChange, json!({ "status": "no_change" }), 0),
		(
			BothAbsentAfterCommonPresent,
			json!({ "status": "both_absent_after_common_present" }),
			0,
		),
		(
			CopyCandidate {
				from: Left,
				target: SyncCopyTarget::AbsentName,
			},
			json!({ "status": "copy_candidate", "from": "left", "target": "absent_name" }),
			0,
		),
		(
			CopyCandidate {
				from: Right,
				target: SyncCopyTarget::ExistingIncumbent,
			},
			json!({ "status": "copy_candidate", "from": "right", "target": "existing_incumbent" }),
			0,
		),
		(
			Conflict(SyncConflict::DivergentVersions),
			json!({ "status": "conflict", "reason": "divergent_versions" }),
			3,
		),
		(
			Conflict(SyncConflict::DeletionAgainstUnchanged { absent: Right }),
			json!({ "status": "conflict", "reason": "deletion_against_unchanged", "absent": "right" }),
			3,
		),
		(
			Conflict(SyncConflict::EditAgainstDeletion { edited: Left }),
			json!({ "status": "conflict", "reason": "edit_against_deletion", "edited": "left" }),
			3,
		),
		(
			Conflict(SyncConflict::UnsupportedEntry),
			json!({ "status": "conflict", "reason": "unsupported_entry" }),
			3,
		),
		(
			Conflict(SyncConflict::AsymmetricBaseline),
			json!({ "status": "conflict", "reason": "asymmetric_baseline" }),
			3,
		),
		(
			Blocked(SyncBlock::IncompleteInventory),
			json!({ "status": "blocked", "reason": "incomplete_inventory" }),
			2,
		),
		(
			Blocked(SyncBlock::UnknownObservation),
			json!({ "status": "blocked", "reason": "unknown_observation" }),
			2,
		),
	];
	for (decision, status, code) in cases {
		assert_eq!(render_decision(decision), (status, code), "{decision:?}");
	}
}

#[test]
fn distinguishes_observed_absence_from_unknown_and_unsupported() {
	let (report, code) = render(
		FirstSyncPreview {
			observations: [SyncObservation::AbsentObserved, SyncObservation::Unknown],
			decision: SyncPathDecision::Blocked(SyncBlock::UnknownObservation),
		},
		[7; 16],
		NonZeroU64::MIN,
	);
	assert_eq!(code, 2);
	assert_eq!(report["scope_complete"], false);
	assert_eq!(report["left"], json!({ "state": "absent_observed" }));
	assert_eq!(report["right"], json!({ "state": "unknown" }));

	let (report, code) = render(
		FirstSyncPreview {
			observations: [
				SyncObservation::UnsupportedEntry,
				SyncObservation::AbsentObserved,
			],
			decision: SyncPathDecision::Conflict(SyncConflict::UnsupportedEntry),
		},
		[7; 16],
		NonZeroU64::MIN,
	);
	assert_eq!(code, 3);
	assert_eq!(report["scope_complete"], true);
	assert_eq!(report["left"], json!({ "state": "unsupported_entry" }));
}
