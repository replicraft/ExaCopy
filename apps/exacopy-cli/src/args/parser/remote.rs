use exacopy_journal::remote_download::finalization_policy::SftpDataOnlyV1;

use std::ffi::{OsStr, OsString};

use clap::builder::PossibleValuesParser;
use clap::{Arg, ArgAction, ArgMatches, Command as Cli};

use super::{
	OPERAND_ORDER, PROFILE, directory_option, operand, output_format, path, path_option,
	selected_format,
};

#[cfg(feature = "experimental-verified-prefix-resume")]
use crate::args::RemoteResumeStrategy;
use crate::args::{
	Command, JobPathDisplay, RemoteCommand, RemoteMetadata, RemoteOptions, RemoteRequest,
};

pub(super) const GET: &str = "get";
pub(super) const REMOTE_RESUME: &str = "remote-resume";
const SSH_PROFILE: &str = "ssh-profile";
const QUALIFICATION: &str = "destination-qualification";
const QUALIFICATION_TRUST: &str = "qualification-trust";
const METADATA: &str = "metadata";
const SHOW_JOB_PATH: &str = "show-job-path";
#[cfg(feature = "experimental-verified-prefix-resume")]
const STRATEGY: &str = "strategy";
#[cfg(feature = "experimental-verified-prefix-resume")]
const VERIFIED_PREFIX: &str = "verified-prefix-with-witness-v1";
#[cfg(feature = "experimental-verified-prefix-resume")]
const RETENTION: &str = "allow-witness-retention";
#[cfg(feature = "experimental-verified-prefix-resume")]
const CONTINUATION_QUALIFICATION: &str = "continuation-qualification";
#[cfg(feature = "experimental-verified-prefix-resume")]
const CONTINUATION_TRUST: &str = "continuation-trust";

pub(super) fn get_subcommand() -> Cli {
	options(
		Cli::new(GET)
			.about("Download one SSH file to an absent local name.")
			.arg(operand("SOURCE", 1))
			.arg(operand("TARGET", 2)),
	)
}

pub(super) fn resume_subcommand() -> Cli {
	witness_options(options(
		Cli::new(REMOTE_RESUME)
			.about("Resume a retained SSH download using its recorded source and target.")
			.arg(operand("JOB", 1)),
	))
}

fn witness_options(cli: Cli) -> Cli {
	#[cfg(feature = "experimental-verified-prefix-resume")]
	{
		cli.arg(
			Arg::new(STRATEGY)
				.long(STRATEGY)
				.value_parser(PossibleValuesParser::new([VERIFIED_PREFIX]))
				.requires_all([RETENTION, CONTINUATION_QUALIFICATION, CONTINUATION_TRUST])
				.help("Independently verify the retained prefix and append only its suffix."),
		)
		.arg(
			Arg::new(RETENTION)
				.long(RETENTION)
				.action(ArgAction::SetTrue)
				.requires(STRATEGY)
				.help("Approve keeping a private hard link to the published file."),
		)
		.arg(
			path_option(
				CONTINUATION_QUALIFICATION,
				"FILE",
				"Select the signed witnessed continuation qualification.",
			)
			.required(false)
			.requires(STRATEGY),
		)
		.arg(
			path_option(
				CONTINUATION_TRUST,
				"FILE",
				"Select the separately protected witnessed qualification trust.",
			)
			.required(false)
			.requires(STRATEGY),
		)
	}
	#[cfg(not(feature = "experimental-verified-prefix-resume"))]
	{
		cli
	}
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
		.arg(
			Arg::new(SHOW_JOB_PATH)
				.long(SHOW_JOB_PATH)
				.action(ArgAction::SetTrue)
				.help("Show the retained local job path and its exact bytes in text output."),
		)
}

pub(super) fn is_remote(command: &str) -> bool {
	matches!(command, GET | REMOTE_RESUME)
}

pub(super) fn is_path_option(arg: &OsStr) -> bool {
	#[cfg(feature = "experimental-verified-prefix-resume")]
	if arg == "--continuation-qualification" || arg == "--continuation-trust" {
		return true;
	}
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
			#[cfg(feature = "experimental-verified-prefix-resume")]
			strategy: resume_strategy(args)?,
		},
		options: read_options(args)?,
	}))
}

#[cfg(feature = "experimental-verified-prefix-resume")]
fn resume_strategy(args: &mut ArgMatches) -> Option<RemoteResumeStrategy> {
	match args.remove_one::<String>(STRATEGY).as_deref() {
		None => Some(RemoteResumeStrategy::Fresh),
		Some(VERIFIED_PREFIX) if args.get_flag(RETENTION) => {
			Some(RemoteResumeStrategy::VerifiedPrefixWithWitness {
				qualification: path(args, CONTINUATION_QUALIFICATION)?,
				trust: path(args, CONTINUATION_TRUST)?,
			})
		}
		_ => None,
	}
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
			job_path_display: if args.get_flag(SHOW_JOB_PATH) {
				JobPathDisplay::Reveal
			} else {
				JobPathDisplay::Redacted
			},
		}),
		_ => None,
	}
}

#[cfg(test)]
mod tests;
