use clap::{Arg, ArgAction, ArgMatches, Command as Cli};
use exacopy_journal::{OwnerProfileId, RootCapabilityId};
use exacopy_platform::macos::staging::jobs::JobName;

use super::super::{
	OPERAND_ORDER, directory_option, operand, output_format, path, selected_format,
};
use crate::args::{Command, InspectApfsCommand};

pub(super) const NAME: &str = "inspect-apfs";
const CONTAINER: &str = "stage-container";
const MANAGED: &str = "managed-apfs";
const PROFILE: &str = "owner-profile-id";
const KEY: &str = "owner-key";
const ROOT: &str = "destination-root-id";

pub(super) fn definition() -> Cli {
	Cli::new(NAME)
		.about("Observe signed history and live names for one retained managed APFS job.")
		.after_help(OPERAND_ORDER)
		.arg(operand("JOB", 1).help("Select the exact canonical .exacopy-UUIDv7 basename."))
		.arg(directory_option(CONTAINER, "Select the existing absolute private container."))
		.arg(
			Arg::new(MANAGED)
				.long(MANAGED)
				.action(ArgAction::SetTrue)
				.required(true)
				.help("Attest the exact materialized, owner-managed local APFS root and private child. Require stable protected ancestry outside File Provider, no automount or external actors or handles, and exclusive locks for all cooperating mutations, including aliases."),
		)
		.arg(selection(PROFILE, "HEX32", "Provide the independently selected owner profile ID."))
		.arg(selection(KEY, "HEX64", "Provide the independently selected Ed25519 public key."))
		.arg(selection(ROOT, "HEX32", "Provide the independently selected destination root ID."))
		.arg(output_format())
}

fn selection(name: &'static str, width: &'static str, help: &'static str) -> Arg {
	Arg::new(name)
		.long(name)
		.value_name(width)
		.required(true)
		.help(help)
}

pub(super) fn command(args: &mut ArgMatches) -> Option<Command> {
	let stage_container = path(args, CONTAINER)?;
	if !args.get_flag(MANAGED) || !stage_container.is_absolute() {
		return None;
	}
	let job = path(args, "JOB")?;
	let profile = args.remove_one::<String>(PROFILE)?;
	let key = args.remove_one::<String>(KEY)?;
	let root = args.remove_one::<String>(ROOT)?;
	Some(Command::InspectApfs(InspectApfsCommand {
		stage_container,
		job: job_name(job.to_str()?)?,
		owner_profile: OwnerProfileId::from_bytes(fixed_hex(&profile)?).ok()?,
		owner_key: fixed_hex(&key)?,
		destination_root: RootCapabilityId::from_bytes(fixed_hex(&root)?).ok()?,
		format: selected_format(args),
	}))
}

fn job_name(name: &str) -> Option<JobName> {
	let uuid = name.strip_prefix(".exacopy-")?;
	if uuid.len() != 36 {
		return None;
	}
	let job = JobName::from_uuid_bytes(fixed_hex(&uuid.replace('-', ""))?).ok()?;
	(job.to_string() == name).then_some(job)
}

fn fixed_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
	let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
	if !remainder.is_empty() || pairs.len() != N {
		return None;
	}
	let mut bytes = [0; N];
	for (byte, [high, low]) in bytes.iter_mut().zip(pairs.iter().copied()) {
		*byte = (nibble(high)? << 4) | nibble(low)?;
	}
	Some(bytes)
}

fn nibble(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte - b'0'),
		b'a'..=b'f' => Some(byte - b'a' + 10),
		_ => None,
	}
}

#[cfg(test)]
mod tests;
