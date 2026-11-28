//! CLI admission using explicit bounded stdin and an independently selected profile.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsFd as _;
use std::path::Path;

use exacopy_platform::linux::{ManagedSyncError, SyncProfileStoreError};
use serde_json::json;

use crate::args::{ManagedSyncInitArgs, SyncManagedCommand};
use crate::assembly::linux::managed_sync::{
	ManagedSyncPreviewError, initialize_approved, inspect_profile_identity, preview_acknowledged,
};
use crate::report::INCONCLUSIVE;

use super::managed_ack::MANAGED_ACK_BYTES;
use super::managed_policy::{MANAGED_POLICY_MAX_BYTES, ManagedPolicyPin};
use super::{managed_report, write_report};

const SCRATCH_BYTES: usize = 64 * 1024;

mod export_recreate;
mod recreate;

pub(crate) fn run_stdio(
	command: SyncManagedCommand,
	stdin: &mut impl Read,
	stdout: &mut io::StdoutLock<'_>,
	stderr: &mut impl Write,
) -> u8 {
	let unavailable = match &command {
		SyncManagedCommand::Init(_) => "exacopy: managed sync Init refused (output_unavailable)",
		SyncManagedCommand::PrepareRecreate(_) => {
			"exacopy: managed sync prepare-recreate refused (output_unavailable)"
		}
		SyncManagedCommand::ExportRecreate { .. } => {
			"exacopy: managed sync export-recreate refused (output_unavailable)"
		}
		_ => return run(command, stdin, stdout, stderr),
	};
	// Stdout can treat EBADF as a successful write. Deliver Init and Plan review
	// evidence through an owned duplicate of the caller's actual descriptor.
	let Ok(descriptor) = stdout.as_fd().try_clone_to_owned() else {
		let _ = writeln!(stderr, "{unavailable}");
		return INCONCLUSIVE;
	};
	run(command, stdin, &mut File::from(descriptor), stderr)
}

fn run(
	command: SyncManagedCommand,
	stdin: &mut impl Read,
	stdout: &mut impl Write,
	stderr: &mut impl Write,
) -> u8 {
	match command {
		SyncManagedCommand::ProfileIdentity { profile } => {
			report_profile_identity(&profile, stdout, stderr)
		}
		SyncManagedCommand::Init(command) => match initialize(&command, stdin) {
			Ok(acknowledgement) => deliver(&acknowledgement, stdout, stderr),
			Err(reason) => {
				let _ = writeln!(stderr, "exacopy: managed sync Init refused ({reason})");
				INCONCLUSIVE
			}
		},
		SyncManagedCommand::PrepareRecreate(command) => {
			recreate::run(&command, stdin, stdout, stderr)
		}
		SyncManagedCommand::ExportRecreate { pair_id, command } => {
			export_recreate::run(&command, pair_id, stdin, stdout, stderr)
		}
		SyncManagedCommand::Preview {
			profile,
			owner_key,
			selection,
		} => {
			let result = read_bounded(stdin, MANAGED_ACK_BYTES).and_then(|bytes| {
				preview_acknowledged(
					&profile,
					owner_key,
					selection,
					&bytes,
					&mut [0; SCRATCH_BYTES],
				)
				.map_err(|refusal| reason(&refusal))
			});
			let (report, exit) = match result {
				Ok((outcome, revision)) => managed_report::render(outcome, selection, revision),
				Err(reason) => (
					json!({
						"status": "blocked",
						"reason": reason,
						"history": "required_p063",
						"scope": "one_subject",
						"scope_complete": false,
						"baseline_advanced": false,
					}),
					INCONCLUSIVE,
				),
			};
			if write_report(&report, stdout).is_err() {
				let _ = writeln!(stderr, "exacopy: could not write managed sync preview");
				INCONCLUSIVE
			} else {
				exit
			}
		}
	}
}

fn report_profile_identity(profile: &Path, stdout: &mut impl Write, stderr: &mut impl Write) -> u8 {
	let identity = match inspect_profile_identity(profile) {
		Ok(identity) => identity,
		Err(error) => {
			let _ = writeln!(
				stderr,
				"exacopy: managed sync profile identity refused ({})",
				reason(&error)
			);
			return INCONCLUSIVE;
		}
	};
	let mut owner_key = String::with_capacity(2 * identity.owner_key.len());
	for byte in identity.owner_key {
		let _ = write!(owner_key, "{byte:02x}");
	}
	let report = json!({
		"owner_profile": uuid::Uuid::from_bytes(identity.owner_profile).simple().to_string(),
		"owner_key": owner_key,
		"device": identity.physical.device().to_string(),
		"inode": identity.physical.inode().to_string(),
	});
	if write_report(&report, stdout).is_err() {
		let _ = writeln!(
			stderr,
			"exacopy: managed sync profile identity output_inconclusive"
		);
		INCONCLUSIVE
	} else {
		0
	}
}

fn initialize(
	command: &ManagedSyncInitArgs,
	stdin: &mut impl Read,
) -> Result<[u8; MANAGED_ACK_BYTES], &'static str> {
	let approved = ManagedPolicyPin::approved_request(
		command.selection,
		command.revision,
		command.owner_key,
		command.approve_request,
	)
	.map_err(|_| "invalid_approval")?;
	let request = read_bounded(stdin, MANAGED_POLICY_MAX_BYTES)?;
	initialize_approved(
		&command.profile,
		command.profile_device,
		command.profile_inode,
		&approved,
		&request,
	)
	.map_err(|refusal| reason(&refusal))
}

fn read_bounded(reader: &mut impl Read, max_bytes: usize) -> Result<Vec<u8>, &'static str> {
	let limit = u64::try_from(max_bytes)
		.ok()
		.and_then(|bound| bound.checked_add(1))
		.ok_or("input_limit")?;
	let mut input = Vec::new();
	reader
		.take(limit)
		.read_to_end(&mut input)
		.map_err(|_| "input_read_failed")?;
	if input.len() > max_bytes {
		Err("input_limit")
	} else {
		Ok(input)
	}
}

fn deliver(
	acknowledgement: &[u8; MANAGED_ACK_BYTES],
	stdout: &mut impl Write,
	stderr: &mut impl Write,
) -> u8 {
	if stdout
		.write_all(acknowledgement)
		.and_then(|()| stdout.flush())
		.is_err()
	{
		let _ = writeln!(
			stderr,
			"exacopy: managed sync Init delivery_uncertain; selection slot retained"
		);
		INCONCLUSIVE
	} else {
		0
	}
}

fn reason(error: &ManagedSyncPreviewError) -> &'static str {
	use ManagedSyncPreviewError as Error;

	match error {
		Error::Selection => "selection_mismatch",
		Error::Acknowledgement => "acknowledgement_refused",
		Error::Policy(_) => "policy_refused",
		Error::Store(SyncProfileStoreError::AlreadyExists) => "selection_occupied",
		Error::CreationUnconfirmed(_)
		| Error::Store(SyncProfileStoreError::CreationUnconfirmed(_)) => "creation_unconfirmed",
		Error::Managed(ManagedSyncError::Busy) | Error::Store(SyncProfileStoreError::Busy) => {
			"busy"
		}
		Error::Store(_) => "profile_custody_refused",
		Error::Native(_) | Error::Managed(_) => "native_scope_refused",
		Error::ReadHistory(error) if error.kind() == io::ErrorKind::NotFound => {
			"selected_history_missing"
		}
		Error::ReadHistory(_) | Error::History(_) => "selected_history_refused",
		Error::Preview(_) => "live_preview_refused",
	}
}

#[cfg(test)]
mod tests;
