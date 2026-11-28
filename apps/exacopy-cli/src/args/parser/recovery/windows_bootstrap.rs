use std::os::windows::ffi::OsStrExt as _;

use clap::{Arg, ArgAction, ArgMatches, Command as Cli, builder::PossibleValuesParser};
use exacopy_journal::windows_bootstrap::{WindowsBootstrapFileIdentity, job_directory_name};
use exacopy_journal::{JournalJobId, OwnerProfileId};

use super::super::{directory_option, path};
use crate::args::{Command, InspectWindowsBootstrapCommand};

pub(super) const NAME: &str = "inspect-windows-bootstrap";
const ROOT: &str = "root";
const GUID: &str = "volume-guid";
const SERIAL: &str = "volume-serial";
const FILE_ID: &str = "root-file-id";
const PROFILE: &str = "owner-profile-id";
const KEY: &str = "owner-key";
const JOB: &str = "job-id";
const MANAGED: &str = "managed-ntfs";

pub(super) fn definition() -> Cli {
	Cli::new(NAME)
		.about("Observe the signed initial history of one retained managed NTFS job.")
		.arg(directory_option(ROOT, "Select the provisioned private root by literal absolute drive path."))
		.arg(selection(GUID, "GUID", "Select the provisioned lowercase hyphenated volume GUID without braces."))
		.arg(selection(SERIAL, "DECIMAL", "Select the provisioned full unsigned 64-bit volume serial."))
		.arg(selection(FILE_ID, "HEX32", "Select the provisioned root file ID in native byte order."))
		.arg(selection(PROFILE, "HEX32", "Provide the independently selected owner profile ID."))
		.arg(selection(KEY, "HEX64", "Provide the independently selected Ed25519 public key."))
		.arg(selection(JOB, "UUIDv7", "Select the canonical lowercase UUIDv7 of the retained job."))
		.arg(
			Arg::new(MANAGED)
				.long(MANAGED)
				.action(ArgAction::SetTrue)
				.required(true)
				.help("Attest a stable independently provisioned private fixed-NTFS root and protected ancestry with no retained untrusted mutation capabilities. Trusted administrators, LocalSystem and equivalent principals, and cooperating current-user processes must leave names, contents, streams, ownership and ACLs unchanged throughout this observation."),
		)
		.arg(
			Arg::new("format")
				.long("format")
				.value_parser(PossibleValuesParser::new(["json"]))
				.help("Emit JSON (the default)."),
		)
}

fn selection(name: &'static str, width: &'static str, help: &'static str) -> Arg {
	Arg::new(name)
		.long(name)
		.value_name(width)
		.required(true)
		.help(help)
}

pub(super) fn command(args: &mut ArgMatches) -> Option<Command> {
	let root = path(args, ROOT)?;
	let mut units = root.as_os_str().encode_wide();
	let drive = u8::try_from(units.next()?).ok()?;
	if !args.get_flag(MANAGED)
		|| !drive.is_ascii_alphabetic()
		|| units.next()? != u16::from(b':')
		|| units.next()? != u16::from(b'\\')
		|| units.next().is_none()
	{
		return None;
	}
	let guid = args.remove_one::<String>(GUID)?;
	let serial = args.remove_one::<String>(SERIAL)?;
	let file_id = args.remove_one::<String>(FILE_ID)?;
	let profile = args.remove_one::<String>(PROFILE)?;
	let key = args.remove_one::<String>(KEY)?;
	let job = args.remove_one::<String>(JOB)?;
	Some(Command::InspectWindowsBootstrap(
		InspectWindowsBootstrapCommand {
			root,
			root_identity: WindowsBootstrapFileIdentity::new(
				guid.as_bytes().try_into().ok()?,
				volume_serial(&serial)?,
				fixed_hex(&file_id)?,
			)
			.ok()?,
			profile: OwnerProfileId::from_bytes(fixed_hex(&profile)?).ok()?,
			owner_key: fixed_hex(&key)?,
			job: job_id(&job)?,
		},
	))
}

fn volume_serial(text: &str) -> Option<u64> {
	if text.len() > 20 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
		return None;
	}
	let serial = text.parse::<u64>().ok()?;
	(serial.to_string() == text).then_some(serial)
}

fn job_id(text: &str) -> Option<JournalJobId> {
	let raw: &[u8; 36] = text.as_bytes().try_into().ok()?;
	let compact = text.replace('-', "");
	let job = JournalJobId::from_bytes(fixed_hex(&compact)?).ok()?;
	let canonical = job_directory_name(job);
	canonical[b".exacopy-".len()..]
		.iter()
		.copied()
		.eq(raw.iter().copied().map(u16::from))
		.then_some(job)
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
