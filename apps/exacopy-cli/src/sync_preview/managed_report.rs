use std::fmt::Write as _;
use std::num::NonZeroU64;

use exacopy_model::{SyncBlock, SyncConflict, SyncCopyTarget, SyncPathDecision};
use exacopy_transfer::linux::sync_preview::{FirstSyncPreview, MAX_PREVIEW_FILE_BYTES};
use serde_json::{Value, json};

use crate::report::INCONCLUSIVE;

use super::linux::{CONFLICT, evidence, side};

/// Projects a managed preview after the caller authenticates the selected history.
pub(super) fn render(
	outcome: FirstSyncPreview,
	selection_id: [u8; 16],
	selection_revision: NonZeroU64,
) -> (Value, u8) {
	let (mut report, exit) = render_decision(outcome.decision);
	let [left, right] = outcome.observations.map(evidence);
	let mut id = String::with_capacity(32);
	for byte in selection_id {
		let _ = write!(id, "{byte:02x}");
	}
	report["left"] = left;
	report["right"] = right;
	report["selection"] = json!({
		"id": id,
		"revision": selection_revision.to_string(),
	});
	report["history"] = json!("authenticated_p063");
	report["scope"] = json!("one_subject");
	report["scope_complete"] = json!(!matches!(outcome.decision, SyncPathDecision::Blocked(_)));
	report["consistency"] = json!("live_observed");
	report["comparison"] = json!("independent_blake3_unnamed_stream");
	report["required_metadata"] = json!("linux_owner_and_mode_v1");
	report["omitted_metadata"] = json!("all_other_metadata");
	report["max_file_bytes"] = json!(MAX_PREVIEW_FILE_BYTES);
	report["baseline_advanced"] = json!(false);
	(report, exit)
}

fn render_decision(decision: SyncPathDecision) -> (Value, u8) {
	use SyncPathDecision::{
		BaselineMatch, Blocked, BothAbsentAfterCommonPresent, Conflict, CopyCandidate, NoChange,
	};

	match decision {
		NoChange => (json!({ "status": "no_change" }), 0),
		BaselineMatch => (json!({ "status": "matching_observations" }), 0),
		BothAbsentAfterCommonPresent => {
			(json!({ "status": "both_absent_after_common_present" }), 0)
		}
		CopyCandidate { from, target } => {
			let target = match target {
				SyncCopyTarget::AbsentName => "absent_name",
				SyncCopyTarget::ExistingIncumbent => "existing_incumbent",
			};
			(
				json!({ "status": "copy_candidate", "from": side(from), "target": target }),
				0,
			)
		}
		Conflict(conflict) => (render_conflict(conflict), CONFLICT),
		Blocked(block) => {
			let reason = match block {
				SyncBlock::IncompleteInventory => "incomplete_inventory",
				SyncBlock::UnknownObservation => "unknown_observation",
			};
			(
				json!({ "status": "blocked", "reason": reason }),
				INCONCLUSIVE,
			)
		}
	}
}

fn render_conflict(conflict: SyncConflict) -> Value {
	match conflict {
		SyncConflict::DivergentVersions => {
			json!({ "status": "conflict", "reason": "divergent_versions" })
		}
		SyncConflict::DeletionAgainstUnchanged { absent } => json!({
			"status": "conflict", "reason": "deletion_against_unchanged", "absent": side(absent),
		}),
		SyncConflict::EditAgainstDeletion { edited } => json!({
			"status": "conflict", "reason": "edit_against_deletion", "edited": side(edited),
		}),
		SyncConflict::UnsupportedEntry => {
			json!({ "status": "conflict", "reason": "unsupported_entry" })
		}
		SyncConflict::AsymmetricBaseline => {
			json!({ "status": "conflict", "reason": "asymmetric_baseline" })
		}
	}
}

#[cfg(test)]
mod tests;
