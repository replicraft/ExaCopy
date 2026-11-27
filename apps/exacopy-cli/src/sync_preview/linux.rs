use std::fmt::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use exacopy_content::MeasureError;
use exacopy_endpoint::linux_staging::StagingSource as _;
use exacopy_endpoint::{IoError, NameError, UnixComponent};
use exacopy_manifest::sync_baseline::LinuxOwnerMode;
use exacopy_model::{SyncConflict, SyncCopyTarget, SyncObservation, SyncPathDecision, SyncSide};
use exacopy_platform::linux::{
	FileIdentity, NamedReadView, ReadError, SyncPreviewEntry, SyncPreviewError, SyncPreviewRoots,
};
use exacopy_transfer::linux::sync_preview::{
	MAX_PREVIEW_FILE_BYTES, PreviewInput, SyncPreviewFailure, preview_without_history,
};
use exacopy_transfer::manifest;
use serde_json::{Value, json};

use crate::args::SyncPreviewCommand;

use super::blocked;

pub(super) const CONFLICT: u8 = 3;
const SCRATCH_BYTES: usize = 64 * 1024;

pub(super) fn preview(command: &SyncPreviewCommand) -> (Value, u8) {
	let [Ok(left_name), Ok(right_name)] = command.roots.each_ref().map(|path| component(path))
	else {
		return blocked("invalid_root_name", None);
	};
	let Ok(subject) = component(&command.subject) else {
		return blocked("invalid_subject_name", None);
	};
	let roots = match SyncPreviewRoots::open(&command.parent, [left_name, right_name]) {
		Ok(roots) => roots,
		Err(error) => return blocked(native_reason(&error), None),
	};
	let selection = roots.selection();
	let pair = match roots.observe(subject) {
		Ok(pair) => pair,
		Err(error) => return blocked(native_reason(&error), None),
	};
	let [left, right] = pair.entries().map(project);
	let [Ok(left), Ok(right)] = [left, right] else {
		return blocked("metadata_unavailable", None);
	};
	let outcome =
		match preview_without_history([left, right], &mut [0; SCRATCH_BYTES], || pair.recheck()) {
			Ok(outcome) => outcome,
			Err(error) => return failure(&error),
		};
	let (mut report, exit) = decision(outcome.decision);
	let [left, right] = outcome.observations.map(evidence);
	report["left"] = left;
	report["right"] = right;
	report["selection"] = json!({
		"parent": native_identity(selection.parent),
		"mount_id": selection.mount_id.to_string(),
		"left_root": native_identity(selection.roots[0]),
		"right_root": native_identity(selection.roots[1]),
		"left_root_name_hex": raw_hex(left_name),
		"right_root_name_hex": raw_hex(right_name),
		"subject_hex": raw_hex(subject),
	});
	report["history"] = json!("none");
	report["scope"] = json!("one_subject");
	report["scope_complete"] = json!(true);
	report["consistency"] = json!("live_observed");
	report["comparison"] = json!("independent_blake3_unnamed_stream");
	report["required_metadata"] = json!("linux_owner_and_mode_v1");
	report["omitted_metadata"] = json!("all_other_metadata");
	report["max_file_bytes"] = json!(MAX_PREVIEW_FILE_BYTES);
	(report, exit)
}

fn component(path: &Path) -> Result<UnixComponent<'_>, NameError> {
	UnixComponent::new(path.as_os_str().as_bytes())
}

fn project<'borrow, 'view>(
	entry: SyncPreviewEntry<'borrow, 'view>,
) -> Result<PreviewInput<'borrow, NamedReadView<'view>>, std::num::TryFromIntError> {
	Ok(match entry {
		SyncPreviewEntry::Present(view) => {
			let metadata = view.metadata();
			PreviewInput::Present {
				view,
				metadata: LinuxOwnerMode {
					mode: u16::try_from(metadata.mode())?,
					uid: metadata.owner(),
					gid: metadata.group(),
				},
			}
		}
		SyncPreviewEntry::Absent => PreviewInput::Absent,
		SyncPreviewEntry::Unsupported => PreviewInput::Unsupported,
	})
}

fn native_reason(error: &SyncPreviewError) -> &'static str {
	match error {
		SyncPreviewError::InvalidParent => "invalid_parent",
		SyncPreviewError::AliasedRoots => "aliased_roots",
		SyncPreviewError::AliasedFiles => "aliased_files",
		SyncPreviewError::UnsupportedMount => "unsupported_mount",
		SyncPreviewError::NameAlias => "inexact_name",
		SyncPreviewError::DirectoryLimit => "resource_limit",
		SyncPreviewError::Changed => "unstable_observation",
		_ => "unknown_observation",
	}
}

fn failure(error: &SyncPreviewFailure<ReadError, SyncPreviewError>) -> (Value, u8) {
	use SyncPreviewFailure as Error;

	match error {
		Error::ScratchLimit => blocked("resource_limit", None),
		Error::FileLimit(which) => blocked("resource_limit", Some(side(*which))),
		Error::Metadata(which, _) => blocked("metadata_unavailable", Some(side(*which))),
		Error::Measure(which, error) => {
			let reason = match error {
				manifest::Error::InitialObservation(
					ReadError::IdentityChanged
					| ReadError::SourceChanged
					| ReadError::UnexpectedDataAfterEnd,
				)
				| manifest::Error::FinalObservation(
					ReadError::IdentityChanged
					| ReadError::SourceChanged
					| ReadError::UnexpectedDataAfterEnd,
				)
				| manifest::Error::Measure(MeasureError::Read {
					source: ReadError::Io(IoError::UnexpectedEof { .. }),
					..
				}) => "unstable_observation",
				_ => "unknown_observation",
			};
			blocked(reason, Some(side(*which)))
		}
		Error::Pair(error) => blocked(native_reason(error), None),
	}
}

fn decision(decision: SyncPathDecision) -> (Value, u8) {
	use SyncPathDecision::{
		BaselineMatch, Blocked, BothAbsentAfterCommonPresent, Conflict, CopyCandidate, NoChange,
	};

	match decision {
		NoChange => (json!({ "status": "no_change" }), 0),
		BaselineMatch => (json!({ "status": "matching_observations" }), 0),
		CopyCandidate {
			from,
			target: SyncCopyTarget::AbsentName,
		} => (
			json!({ "status": "copy_candidate", "from": side(from), "target": "absent_name" }),
			0,
		),
		Conflict(SyncConflict::DivergentVersions) => (
			json!({ "status": "conflict", "reason": "divergent_versions" }),
			CONFLICT,
		),
		Conflict(SyncConflict::UnsupportedEntry) => (
			json!({ "status": "conflict", "reason": "unsupported_entry" }),
			CONFLICT,
		),
		Blocked(_) => blocked("unknown_observation", None),
		BothAbsentAfterCommonPresent | CopyCandidate { .. } | Conflict(_) => {
			blocked("unexpected_history_decision", None)
		}
	}
}

pub(super) fn side(side: SyncSide) -> &'static str {
	match side {
		SyncSide::Left => "left",
		SyncSide::Right => "right",
	}
}

pub(super) fn evidence(observation: SyncObservation) -> Value {
	match observation {
		SyncObservation::Present(file) => json!({
			"state": "present",
			"bytes": file.byte_len,
			"stream_digest": blake3::Hash::from_bytes(file.content_digest).to_hex().as_str(),
			"required_metadata_digest": blake3::Hash::from_bytes(file.required_metadata_digest).to_hex().as_str(),
		}),
		SyncObservation::AbsentObserved => json!({ "state": "absent_observed" }),
		SyncObservation::Unknown => json!({ "state": "unknown" }),
		SyncObservation::UnsupportedEntry => json!({ "state": "unsupported_entry" }),
	}
}

fn native_identity(identity: FileIdentity) -> Value {
	json!({
		"device": identity.device().to_string(),
		"inode": identity.inode().to_string(),
	})
}

fn raw_hex(name: UnixComponent<'_>) -> String {
	let bytes = name.as_bytes();
	let mut output = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		let _ = write!(output, "{byte:02x}");
	}
	output
}
