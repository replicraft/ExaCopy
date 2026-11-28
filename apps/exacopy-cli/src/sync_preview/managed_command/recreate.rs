use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::num::NonZeroU64;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use exacopy_model::{SyncConflict, SyncSide};
use exacopy_plan::{PlanBody, PlanCreationTime, plan_reference};
use exacopy_platform::linux::FileIdentity;
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::assembly::linux::managed_sync::{
	ManualRecreateCandidate, ManualRecreateError, ManualRecreatePlanIds,
	prepare_recreate_acknowledged,
};
use crate::profile::kernel_random;
use crate::report::INCONCLUSIVE;

use super::{MANAGED_ACK_BYTES, SCRATCH_BYTES, read_bounded, reason};

#[derive(Serialize)]
struct Report {
	schema: &'static str,
	schema_version: &'static str,
	authority: &'static str,
	approval_required: bool,
	copy_started: bool,
	baseline_advanced: bool,
	#[serde(flatten)]
	outcome: Outcome,
}

#[derive(Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum Outcome {
	Prepared { review: Value },
	Refused { reason: &'static str },
}

impl Report {
	fn new(outcome: Outcome) -> Self {
		Self {
			schema: "exacopy.cli.managed_sync_recreate_plan",
			schema_version: "1.0",
			authority: "none",
			approval_required: true,
			copy_started: false,
			baseline_advanced: false,
			outcome,
		}
	}

	fn write(&self, output: &mut impl Write) -> io::Result<()> {
		serde_json::to_writer(&mut *output, self)?;
		writeln!(output)?;
		output.flush()
	}
}

pub(super) fn run(
	profile: &Path,
	owner_key: [u8; 32],
	selection: [u8; 16],
	reviewed: (SyncSide, SyncConflict),
	stdin: &mut impl Read,
	stdout: &mut impl Write,
	stderr: &mut impl Write,
) -> u8 {
	let observed = (|| {
		let receipt = read_bounded(stdin, MANAGED_ACK_BYTES)?;
		let ids = plan_ids()?;
		prepare_recreate_acknowledged(
			profile,
			owner_key,
			selection,
			&receipt,
			reviewed,
			ids,
			&mut [0; SCRATCH_BYTES],
		)
		.map_err(recreate_reason)
		.and_then(|(candidate, revision)| review(selection, revision, &candidate))
	})();
	let (outcome, status) = match observed {
		Ok(review) => (Outcome::Prepared { review }, 0),
		Err(reason) => (Outcome::Refused { reason }, INCONCLUSIVE),
	};
	if Report::new(outcome).write(stdout).is_err() {
		let _ = writeln!(
			stderr,
			"exacopy: managed sync prepare-recreate output_inconclusive"
		);
		INCONCLUSIVE
	} else {
		status
	}
}

fn review(
	selection: [u8; 16],
	revision: NonZeroU64,
	candidate: &ManualRecreateCandidate,
) -> Result<Value, &'static str> {
	let child = &candidate.child;
	let body = PlanBody::from_canonical_cbor(child.digest(), child.canonical_body())
		.map_err(|_| "child_plan_evidence_refused")?;
	if !body.fields().approval_required {
		return Err("child_plan_evidence_refused");
	}
	let conflict = match candidate.conflict {
		SyncConflict::DeletionAgainstUnchanged { .. } => "deletion-against-unchanged",
		SyncConflict::EditAgainstDeletion { .. } => "edit-against-deletion",
		_ => return Err("reviewed_conflict_changed"),
	};
	let source = candidate.source;
	Ok(json!({
		"selection": { "id": hex(&selection), "revision": revision.to_string() },
		"policy_digest": hex(&candidate.policy_digest),
		"predecessor_digest": hex(&candidate.predecessor_digest),
		"history": "authenticated_p063",
		"subject_bytes_hex": hex(&candidate.subject),
		"from": match candidate.from { SyncSide::Left => "left", SyncSide::Right => "right" },
		"reviewed_conflict": conflict,
		"roots": candidate.roots.map(|root| json!({
			"managed_locator": hex(&root.managed_locator),
			"observed_identity": identity(root.observed_identity),
			"child_alias": root.child_alias.to_string(),
		})),
		"source": {
			"observed_identity": identity(candidate.source_identity),
			"bytes": source.byte_len.to_string(),
			"stream_digest": hex(&source.content_digest),
			"required_metadata_digest": hex(&source.required_metadata_digest),
		},
		"child_plan": {
			"body_digest": hex(&child.digest()),
			"body_cbor_hex": hex(child.canonical_body()),
			"entry_page_cbor_hex": hex(child.canonical_page()),
		},
	}))
}

fn identity(identity: FileIdentity) -> Value {
	json!({
		"device": identity.device().to_string(),
		"inode": identity.inode().to_string(),
	})
}

fn recreate_reason(error: ManualRecreateError) -> &'static str {
	match error {
		ManualRecreateError::Scope(error) => reason(&error),
		ManualRecreateError::ReviewChanged => "reviewed_conflict_changed",
		ManualRecreateError::PeerFileLimit => "peer_read_limit",
		ManualRecreateError::Plan(_) => "child_plan_refused",
		ManualRecreateError::PlanEvidence => "child_plan_evidence_refused",
	}
}

fn plan_ids() -> Result<ManualRecreatePlanIds, &'static str> {
	let elapsed = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_err(|_| "clock_unavailable")?;
	let creation = PlanCreationTime::new(elapsed).ok_or("clock_unavailable")?;
	let mut entropy = [0; 10];
	kernel_random(&mut entropy).map_err(|_| "entropy_unavailable")?;
	Ok(ManualRecreatePlanIds {
		plan: creation.plan_id(&entropy),
		entry: fresh_reference()?,
		source_view: fresh_reference()?,
		measurement: fresh_reference()?,
		observed_at: creation.timestamp(),
	})
}

fn fresh_reference() -> Result<Uuid, &'static str> {
	let mut entropy = [0; 16];
	kernel_random(&mut entropy).map_err(|_| "entropy_unavailable")?;
	Ok(plan_reference(entropy))
}

fn hex(bytes: &[u8]) -> String {
	let mut result = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		write!(result, "{byte:02x}").expect("writing to a String succeeds");
	}
	result
}

#[cfg(test)]
mod tests;
