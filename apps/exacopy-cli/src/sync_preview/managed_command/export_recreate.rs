use std::fmt::Write as _;
use std::io::{self, Read, Write};

use exacopy_plan::UnixTimestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::args::ManagedSyncRecreateArgs;
use crate::assembly::linux::managed_sync::{
	SignedRecreateError, SignedRecreateExport, SignedRecreateRequest, export_recreate_acknowledged,
};
use crate::profile::kernel_random;
use crate::report::INCONCLUSIVE;

use super::recreate::{creation_time, fresh_reference, plan_ids_at, recreate_reason};
use super::{MANAGED_ACK_BYTES, SCRATCH_BYTES, read_bounded, reason};

const SCHEMA: &str = "exacopy.cli.managed_sync_recreate_export";
const VERSION: &str = "1.0";
const MAX_REPORT_BYTES: usize = 64 * 1024;
const MAX_MEMBER_BYTES: usize = 2_048;
const MAX_BUNDLE_BYTES: usize = 16 * 1024;

pub(super) fn run(
	command: &ManagedSyncRecreateArgs,
	pair_id: [u8; 16],
	stdin: &mut impl Read,
	stdout: &mut impl Write,
	stderr: &mut impl Write,
) -> u8 {
	let result = produce(command, pair_id, stdin).and_then(|(export, created, expires)| {
		let encoded = Report::exported(&export).canonical_json(Some(&export))?;
		let checked = wall_time().ok_or("clock_unavailable")?;
		if checked < created || checked >= expires {
			return Err("child_plan_expired");
		}
		Ok(encoded)
	});
	let (encoded, status) = match result {
		Ok(bytes) => (Ok(bytes), 0),
		Err(cause) => (Report::refused(cause).canonical_json(None), INCONCLUSIVE),
	};
	match encoded.and_then(|bytes| write_report(stdout, &bytes).map_err(|_| "output_inconclusive"))
	{
		Ok(()) => status,
		Err(cause) => {
			let _ = writeln!(stderr, "exacopy: managed sync export-recreate {cause}");
			INCONCLUSIVE
		}
	}
}

fn produce(
	command: &ManagedSyncRecreateArgs,
	pair_id: [u8; 16],
	stdin: &mut impl Read,
) -> Result<(SignedRecreateExport, UnixTimestamp, UnixTimestamp), &'static str> {
	let acknowledgement = read_bounded(stdin, MANAGED_ACK_BYTES)?;
	let creation = creation_time()?;
	let (ids, expires) = plan_ids_at(creation, command.expires_in_seconds)?;
	let expires_at = expires.ok_or("child_plan_expiry_required")?;
	let mut entropy = [0; 10];
	kernel_random(&mut entropy).map_err(|_| "entropy_unavailable")?;
	let parent_id = *creation.plan_id(&entropy).as_bytes();
	let action_id = *fresh_reference()?.as_bytes();
	let exported = export_recreate_acknowledged(
		SignedRecreateRequest {
			profile: &command.profile,
			owner_key: command.owner_key,
			selection: command.selection,
			acknowledgement: &acknowledgement,
			pair_id,
			parent_id,
			action_id,
			from: command.from,
			reviewed: command.reviewed,
			ids,
			expires_at,
		},
		&mut [0; SCRATCH_BYTES],
		wall_time,
	)
	.map_err(|error| match error {
		SignedRecreateError::Scope(cause) => reason(&cause),
		SignedRecreateError::Planning(cause) => recreate_reason(cause),
		SignedRecreateError::Custody => "signing_custody_refused",
		SignedRecreateError::Clock => "child_plan_expired_or_clock_unavailable",
		SignedRecreateError::Bundle => "signed_bundle_refused",
	})?;
	Ok((exported, ids.observed_at, expires_at))
}

fn wall_time() -> Option<UnixTimestamp> {
	creation_time().ok().map(|creation| creation.timestamp())
}

fn write_report(stdout: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
	stdout.write_all(bytes)?;
	stdout.flush()
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Report {
	schema: String,
	schema_version: String,
	authority: String,
	approval_required: bool,
	approval_present: bool,
	delegated_grant_present: bool,
	action_intent_present: bool,
	copy_started: bool,
	baseline_advanced: bool,
	result: ExportResult,
	#[serde(skip_serializing_if = "Option::is_none")]
	pair_id: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	predecessor_pair_digest: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	parent_plan_digest: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	bundle: Option<Members>,
	#[serde(skip_serializing_if = "Option::is_none")]
	reason: Option<String>,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExportResult {
	Exported,
	Refused,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Members {
	parent_envelope_cbor_hex: String,
	action_page_cbor_hex: String,
	child_plan_body_cbor_hex: String,
	child_plan_page_cbor_hex: String,
	predecessor_root_envelope_cbor_hex: String,
	left_endpoint_envelope_cbor_hex: String,
	right_endpoint_envelope_cbor_hex: String,
	predecessor_leaf_cbor_hex: String,
}

impl Report {
	fn base(result: ExportResult) -> Self {
		Self {
			schema: "exacopy.cli.managed_sync_recreate_export".into(),
			schema_version: "1.0".into(),
			authority: "none".into(),
			approval_required: true,
			approval_present: false,
			delegated_grant_present: false,
			action_intent_present: false,
			copy_started: false,
			baseline_advanced: false,
			result,
			pair_id: None,
			predecessor_pair_digest: None,
			parent_plan_digest: None,
			bundle: None,
			reason: None,
		}
	}

	fn exported(source: &SignedRecreateExport) -> Self {
		Self {
			pair_id: Some(Uuid::from_bytes(source.pair_id).hyphenated().to_string()),
			predecessor_pair_digest: Some(hex(&source.predecessor_pair_digest)),
			parent_plan_digest: Some(hex(&source.parent_digest)),
			bundle: Some(Members::encode(&source.members)),
			..Self::base(ExportResult::Exported)
		}
	}

	fn refused(reason: &str) -> Self {
		Self {
			reason: Some(reason.into()),
			..Self::base(ExportResult::Refused)
		}
	}

	fn canonical_json(
		&self,
		source: Option<&SignedRecreateExport>,
	) -> Result<Vec<u8>, &'static str> {
		const REFUSED: &str = "report_binding_refused";
		let mut encoded = serde_json::to_vec(self).map_err(|_| REFUSED)?;
		encoded.push(b'\n');
		let decoded = Self::decode(&encoded).ok_or(REFUSED)?;
		if !decoded.matches(source, self.reason.as_deref()) {
			return Err(REFUSED);
		}
		Ok(encoded)
	}

	fn decode(input: &[u8]) -> Option<Self> {
		if input.len() > MAX_REPORT_BYTES {
			return None;
		}
		let document = input.strip_suffix(b"\n")?;
		let report: Self = serde_json::from_slice(document).ok()?;
		let mut canonical = vec![0; document.len()];
		let mut output = io::Cursor::new(canonical.as_mut_slice());
		serde_json::to_writer(&mut output, &report).ok()?;
		let written = usize::try_from(output.position()).ok()?;
		(written == document.len() && document == canonical.as_slice()).then_some(report)
	}

	fn matches(&self, source: Option<&SignedRecreateExport>, reason: Option<&str>) -> bool {
		if self.schema != SCHEMA
			|| self.schema_version != VERSION
			|| self.authority != "none"
			|| !self.approval_required
			|| self.approval_present
			|| self.delegated_grant_present
			|| self.action_intent_present
			|| self.copy_started
			|| self.baseline_advanced
		{
			return false;
		}
		match source {
			Some(source) => {
				let pair = Uuid::from_bytes(source.pair_id).hyphenated().to_string();
				self.result == ExportResult::Exported
					&& self.reason.is_none()
					&& self.pair_id.as_deref() == Some(pair.as_str())
					&& self
						.predecessor_pair_digest
						.as_deref()
						.is_some_and(|digest| matches_hex(digest, &source.predecessor_pair_digest))
					&& self
						.parent_plan_digest
						.as_deref()
						.is_some_and(|digest| matches_hex(digest, &source.parent_digest))
					&& self
						.bundle
						.as_ref()
						.is_some_and(|bundle| bundle.matches(&source.members))
			}
			None => {
				self.result == ExportResult::Refused
					&& reason.is_some()
					&& self.reason.as_deref() == reason
					&& self.pair_id.is_none()
					&& self.predecessor_pair_digest.is_none()
					&& self.parent_plan_digest.is_none()
					&& self.bundle.is_none()
			}
		}
	}
}

impl Members {
	fn encode(bytes: &[Vec<u8>; 8]) -> Self {
		let [parent, action, child, page, root, left, right, leaf] =
			bytes.each_ref().map(|v| hex(v));
		Self {
			parent_envelope_cbor_hex: parent,
			action_page_cbor_hex: action,
			child_plan_body_cbor_hex: child,
			child_plan_page_cbor_hex: page,
			predecessor_root_envelope_cbor_hex: root,
			left_endpoint_envelope_cbor_hex: left,
			right_endpoint_envelope_cbor_hex: right,
			predecessor_leaf_cbor_hex: leaf,
		}
	}

	fn matches(&self, source: &[Vec<u8>; 8]) -> bool {
		let members = [
			&self.parent_envelope_cbor_hex,
			&self.action_page_cbor_hex,
			&self.child_plan_body_cbor_hex,
			&self.child_plan_page_cbor_hex,
			&self.predecessor_root_envelope_cbor_hex,
			&self.left_endpoint_envelope_cbor_hex,
			&self.right_endpoint_envelope_cbor_hex,
			&self.predecessor_leaf_cbor_hex,
		];
		members
			.iter()
			.all(|s| (2..=MAX_MEMBER_BYTES * 2).contains(&s.len()))
			&& members.iter().map(|s| s.len()).sum::<usize>() <= MAX_BUNDLE_BYTES * 2
			&& members
				.into_iter()
				.zip(source)
				.all(|(s, bytes)| matches_hex(s, bytes))
	}
}

fn matches_hex(text: &str, bytes: &[u8]) -> bool {
	const HEX: &[u8; 16] = b"0123456789abcdef";
	text.len() == bytes.len() * 2
		&& text
			.as_bytes()
			.as_chunks::<2>()
			.0
			.iter()
			.zip(bytes)
			.all(|(pair, &byte)| {
				*pair == [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]]
			})
}

fn hex(bytes: &[u8]) -> String {
	let mut out = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		write!(out, "{byte:02x}").expect("writing to a String succeeds");
	}
	out
}

#[cfg(test)]
mod tests;
