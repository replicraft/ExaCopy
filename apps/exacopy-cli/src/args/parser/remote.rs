use exacopy_journal::remote_download::finalization_policy::SftpDataOnlyV1;

use std::ffi::{OsStr, OsString};

use clap::builder::PossibleValuesParser;
use clap::{Arg, ArgMatches, Command as Cli};

use super::{
	OPERAND_ORDER, PROFILE, directory_option, operand, output_format, path, path_option,
	selected_format,
};

use crate::args::{Command, RemoteCommand, RemoteMetadata, RemoteOptions, RemoteRequest};

pub(super) const GET: &str = "get";
pub(super) const REMOTE_RESUME: &str = "remote-resume";
const SSH_PROFILE: &str = "ssh-profile";
const QUALIFICATION: &str = "destination-qualification";
const QUALIFICATION_TRUST: &str = "qualification-trust";
const METADATA: &str = "metadata";

pub(super) fn get_subcommand() -> Cli {
	options(
		Cli::new(GET)
			.about("Download one SSH file to an absent local name.")
			.arg(operand("SOURCE", 1))
			.arg(operand("TARGET", 2)),
	)
}

pub(super) fn resume_subcommand() -> Cli {
	options(
		Cli::new(REMOTE_RESUME)
			.about("Resume a retained SSH download using its recorded source and target.")
			.arg(operand("JOB", 1)),
	)
}

fn options(cli: Cli) -> Cli {
	cli.after_help(OPERAND_ORDER)
		.arg(directory_option(
			PROFILE,
			"Select the private owner profile.",
		))
		.arg(path_option(
			SSH_PROFILE,
			"FILE",
			"Select the protected SSH profile.",
		))
		.arg(path_option(
			QUALIFICATION,
			"FILE",
			"Select the signed destination qualification artifact.",
		))
		.arg(path_option(
			QUALIFICATION_TRUST,
			"FILE",
			"Select the separately protected attestor trust and campaign scope.",
		))
		.arg(
			Arg::new(METADATA)
				.long(METADATA)
				.required(true)
				.value_parser(PossibleValuesParser::new([SftpDataOnlyV1::NAME]))
				.help("Accept the SFTP data-only metadata policy and its reported omissions."),
		)
		.arg(output_format())
}

pub(super) fn is_remote(command: &str) -> bool {
	matches!(command, GET | REMOTE_RESUME)
}

pub(super) fn is_path_option(arg: &OsStr) -> bool {
	arg == "--profile"
		|| arg == "--ssh-profile"
		|| arg == "--destination-qualification"
		|| arg == "--qualification-trust"
}

pub(super) fn get(args: &mut ArgMatches) -> Option<Command> {
	let request = RemoteRequest::Get {
		source: args.remove_one::<OsString>("SOURCE")?,
		target: path(args, "TARGET")?,
	};
	Some(Command::Remote(RemoteCommand {
		request,
		options: read_options(args)?,
	}))
}

pub(super) fn resume(args: &mut ArgMatches) -> Option<Command> {
	Some(Command::Remote(RemoteCommand {
		request: RemoteRequest::Resume {
			job: path(args, "JOB")?,
		},
		options: read_options(args)?,
	}))
}

fn read_options(args: &mut ArgMatches) -> Option<RemoteOptions> {
	match args.get_one::<String>(METADATA)?.as_str() {
		SftpDataOnlyV1::NAME => Some(RemoteOptions {
			profile: path(args, PROFILE)?,
			ssh_profile: path(args, SSH_PROFILE)?,
			destination_qualification: path(args, QUALIFICATION)?,
			qualification_trust: path(args, QUALIFICATION_TRUST)?,
			metadata: RemoteMetadata::SftpDataOnlyV1,
			format: selected_format(args),
		}),
		_ => None,
	}
}

#[cfg(test)]
mod tests;
