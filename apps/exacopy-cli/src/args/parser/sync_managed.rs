use std::ffi::OsString;
use std::num::NonZeroU64;

use clap::builder::OsStringValueParser;
use clap::{Arg, ArgAction, ArgMatches, Command as Cli};
use exacopy_model::{SyncConflict, SyncSide};

use crate::args::{ManagedSyncInitArgs, SyncManagedCommand};

use super::{INIT, PROFILE, path};

pub(super) const NAME: &str = "sync-managed";
const PREVIEW: &str = "preview";
const PREPARE_RECREATE: &str = "prepare-recreate";
const FROM: &str = "from";
const REVIEWED_CONFLICT: &str = "reviewed-conflict";
const PROFILE_IDENTITY: &str = "profile-identity";
const PROFILE_DEVICE: &str = "profile-device";
const PROFILE_INODE: &str = "profile-inode";
const OWNER_KEY: &str = "owner-key";
const SELECTION: &str = "selection";
const REVISION: &str = "revision";
const APPROVE_REQUEST: &str = "approve-request";
const REQUEST_STDIN: &str = "request-stdin";
const RECEIPT_STDIN: &str = "receipt-stdin";

pub(super) fn definition() -> Cli {
	Cli::new(NAME)
		.about("Inspect, initialize, preview, or prepare a review Plan for one managed subject.")
		.disable_help_subcommand(true)
		.subcommand_required(true)
		.subcommand(profile_command(
			PROFILE_IDENTITY,
			"Report the selected profile's public owner identity and physical directory identity.",
		))
		.subcommand(
			selected_profile(
				INIT,
				"Initialize one immutable managed synchronization selection.",
			)
			.arg(value(
				PROFILE_DEVICE,
				"DECIMAL",
				"Exact device number of the selected profile.",
			))
			.arg(value(
				PROFILE_INODE,
				"NONZERO_DECIMAL",
				"Exact inode of the selected profile.",
			))
			.arg(value(
				REVISION,
				"NONZERO_DECIMAL",
				"Independently selected positive revision.",
			))
			.arg(value(
				APPROVE_REQUEST,
				"64HEX",
				"Independently approved canonical managed policy commitment.",
			))
			.arg(stdin(
				REQUEST_STDIN,
				"Read the bounded initialization request from stdin.",
			)),
		)
		.subcommand(
			selected_profile(
				PREVIEW,
				"Preview the selected subject using authenticated history.",
			)
			.arg(stdin(
				RECEIPT_STDIN,
				"Read the independently retained selection receipt from stdin.",
			)),
		)
		.subcommand(
			selected_profile(
				PREPARE_RECREATE,
				"Prepare an unsigned manual recreate Plan for review.",
			)
			.arg(stdin(
				RECEIPT_STDIN,
				"Read the independently retained selection receipt from stdin.",
			))
			.arg(value(
				FROM,
				"left|right",
				"Select the surviving source explicitly.",
			))
			.arg(value(
				REVIEWED_CONFLICT,
				"CONFLICT",
				"Select deletion-against-unchanged or edit-against-deletion.",
			)),
		)
}

fn selected_profile(name: &'static str, about: &'static str) -> Cli {
	profile_command(name, about)
		.arg(value(
			OWNER_KEY,
			"64HEX",
			"Independently selected public owner key.",
		))
		.arg(value(
			SELECTION,
			"32HEX",
			"Independently selected nonzero selection ID.",
		))
}

fn profile_command(name: &'static str, about: &'static str) -> Cli {
	Cli::new(name).about(about).arg(value(
		PROFILE,
		"ABSOLUTE_PATH",
		"Exact existing owner-private profile directory.",
	))
}

fn value(name: &'static str, value_name: &'static str, help: &'static str) -> Arg {
	Arg::new(name)
		.long(name)
		.value_name(value_name)
		.required(true)
		.value_parser(OsStringValueParser::new())
		.help(help)
}

fn stdin(name: &'static str, help: &'static str) -> Arg {
	Arg::new(name)
		.long(name)
		.required(true)
		.action(ArgAction::SetTrue)
		.help(help)
}

pub(super) fn command(mut command: ArgMatches) -> Option<SyncManagedCommand> {
	let (operation, mut args) = command.remove_subcommand()?;
	let profile = path(&mut args, PROFILE)?;
	if !canonical_absolute(profile.as_os_str().as_encoded_bytes()) {
		return None;
	}
	if operation == PROFILE_IDENTITY {
		return Some(SyncManagedCommand::ProfileIdentity { profile });
	}
	let owner_key = hex(bytes(&args, OWNER_KEY)?)?;
	let selection = hex(bytes(&args, SELECTION)?)?;
	if selection == [0; 16] {
		return None;
	}
	match operation.as_str() {
		INIT if args.get_flag(REQUEST_STDIN) => {
			Some(SyncManagedCommand::Init(ManagedSyncInitArgs {
				profile,
				profile_device: decimal(bytes(&args, PROFILE_DEVICE)?)?,
				profile_inode: NonZeroU64::new(decimal(bytes(&args, PROFILE_INODE)?)?)?,
				owner_key,
				selection,
				revision: NonZeroU64::new(decimal(bytes(&args, REVISION)?)?)?,
				approve_request: hex(bytes(&args, APPROVE_REQUEST)?)?,
			}))
		}
		PREVIEW if args.get_flag(RECEIPT_STDIN) => Some(SyncManagedCommand::Preview {
			profile,
			owner_key,
			selection,
		}),
		PREPARE_RECREATE if args.get_flag(RECEIPT_STDIN) => {
			let (from, absent) = match bytes(&args, FROM)? {
				b"left" => (SyncSide::Left, SyncSide::Right),
				b"right" => (SyncSide::Right, SyncSide::Left),
				_ => return None,
			};
			let reviewed = match bytes(&args, REVIEWED_CONFLICT)? {
				b"deletion-against-unchanged" => SyncConflict::DeletionAgainstUnchanged { absent },
				b"edit-against-deletion" => SyncConflict::EditAgainstDeletion { edited: from },
				_ => return None,
			};
			Some(SyncManagedCommand::PrepareRecreate {
				profile,
				owner_key,
				selection,
				from,
				reviewed,
			})
		}
		_ => None,
	}
}

fn bytes<'args>(args: &'args ArgMatches, name: &str) -> Option<&'args [u8]> {
	Some(args.get_one::<OsString>(name)?.as_encoded_bytes())
}

fn canonical_absolute(raw: &[u8]) -> bool {
	raw.strip_prefix(b"/").is_some_and(|tail| {
		tail.split(|&byte| byte == b'/')
			.all(|part| !matches!(part, b"" | b"." | b"..") && !part.contains(&0))
	})
}

fn decimal(raw: &[u8]) -> Option<u64> {
	if raw.is_empty() || raw.len() > 20 || (raw.len() > 1 && raw[0] == b'0') {
		return None;
	}
	raw.iter().try_fold(0_u64, |number, &digit| {
		if !digit.is_ascii_digit() {
			return None;
		}
		number.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
	})
}

fn hex<const N: usize>(raw: &[u8]) -> Option<[u8; N]> {
	let (pairs, remainder) = raw.as_chunks::<2>();
	if pairs.len() != N || !remainder.is_empty() {
		return None;
	}
	let mut result = [0; N];
	for (&[high, low], output) in pairs.iter().zip(&mut result) {
		*output = (hex_digit(high)? << 4) | hex_digit(low)?;
	}
	Some(result)
}

fn hex_digit(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte - b'0'),
		b'a'..=b'f' => Some(byte - b'a' + 10),
		_ => None,
	}
}

#[cfg(test)]
mod tests;
