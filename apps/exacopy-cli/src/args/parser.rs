use std::ffi::{OsStr, OsString};
use std::num::NonZeroUsize;
use std::path::PathBuf;

use clap::builder::{OsStringValueParser, PossibleValuesParser};
use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{Arg, ArgAction, ArgMatches, Command as Cli};

use super::{
	Command, CopyCommand, DiffCommand, DiffProfile, Format, PlanCommand, RecoveryAction,
	RecoveryCommand, SourceRecoveryAction, VerifyCommand,
};

const DIFF: &str = "diff";
const COPY: &str = "copy";
const PLAN: &str = "plan";
const OUTPUT: &str = "output";
const MANIFEST: &str = "manifest";
const CREATE: &str = "create";
const VERIFY: &str = "verify";
const RECOVER: &str = "recover";
const PROFILE: &str = "profile";
const INIT: &str = "init";
const INSPECT: &str = "inspect";
const FINISH: &str = "finish";
const RETRY: &str = "retry";
const RESUME: &str = "resume";
const FORMAT: &str = "format";
const SOURCE_ROOT: &str = "source-root";
const WORKERS: &str = "workers";
const MANAGED_MACOS: &str = "managed-macos";
const LOCAL_NTFS: &str = "local-ntfs";
#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
mod remote;
#[cfg(test)]
mod tests;

const MAX_DIFF_WORKERS: u8 = 16;

#[cfg(any(
	target_os = "linux",
	target_os = "macos",
	all(target_os = "windows", feature = "experimental-windows-diff")
))]
const _: () = assert!(
	MAX_DIFF_WORKERS as usize == exacopy_diff::MAX_WORKERS,
	"the CLI worker limit must match the comparison engine"
);

const OPERAND_ORDER: &str = "Supply the path operands before the options. Use -- before the operands to pass dash-prefixed names.";

const MANAGED_APFS: &str = "Attest that both input parent paths stably resolve to the exact provisioned, owner-private, materialized local APFS roots outside File Provider. Use protected ancestors and a trusted mount namespace with no automounts or remote or provider lookups. Outside actors must hold no access handles, and same-user writers must take exclusive directory locks, including across aliases.";

pub(crate) fn parse(args: impl Iterator<Item = OsString>) -> Result<Command, String> {
	let mut args: Vec<OsString> = args.collect();
	let standalone_version =
		matches!(args.as_slice(), [flag] if flag == "--version" || flag == "-V");
	let mut cli = definition();
	cli.build();
	let (scope, prefix) = command_scope(&cli, &args);
	let mut diagnostic_scope = scope.clone();
	frame_operands(scope, prefix, &mut args)
		.map_err(|message| invalid_invocation(&mut diagnostic_scope, message))?;
	match cli.try_get_matches_from(args) {
		Ok(matches) => typed_command(matches).ok_or_else(|| {
			invalid_invocation(&mut diagnostic_scope, "could not interpret the command")
		}),
		Err(error) if error.kind() == ErrorKind::DisplayHelp => {
			Ok(Command::Help(error.to_string()))
		}
		Err(error) if error.kind() == ErrorKind::DisplayVersion => {
			if standalone_version {
				Ok(Command::Version)
			} else {
				Err(invalid_invocation(
					&mut diagnostic_scope,
					"request version by itself",
				))
			}
		}
		Err(error) => Err(invalid_invocation(
			&mut diagnostic_scope,
			error_message(&error),
		)),
	}
}

fn definition() -> Cli {
	let cli = Cli::new("exacopy")
		.bin_name("exacopy")
		.version(env!("CARGO_PKG_VERSION"))
		.about("Compare, verify, or copy regular files and recover retained copies.")
		.no_binary_name(true)
		.disable_help_subcommand(true)
		.subcommand_required(true)
		.subcommand(
			Cli::new(DIFF)
				.about("Compare the exact bytes of two regular files.")
				.after_help(OPERAND_ORDER)
				.arg(operand("LEFT", 1))
				.arg(operand("RIGHT", 2))
				.arg(
					Arg::new("compare")
						.long("compare")
						.value_parser(PossibleValuesParser::new(["bytes"]))
						.help("Select exact byte comparison, the default relation."),
				)
				.arg(
					Arg::new(WORKERS)
						.long(WORKERS)
						.allow_negative_numbers(true)
						.value_name("N")
						.value_parser(
							clap::value_parser!(u8).range(1..=i64::from(MAX_DIFF_WORKERS)),
						)
						.help("Set the positioned-read worker ceiling from 1 through 16."),
				)
				.arg(
					Arg::new(MANAGED_MACOS)
						.long(MANAGED_MACOS)
						.action(ArgAction::SetTrue)
						.help(MANAGED_APFS),
				)
				.arg(
					Arg::new(LOCAL_NTFS)
						.long(LOCAL_NTFS)
						.action(ArgAction::SetTrue)
						.conflicts_with(MANAGED_MACOS)
						.help(
							"Select experimental live NTFS comparison through literal absolute drive paths on Windows.",
						),
				)
				.arg(output_format()),
		)
		.subcommand(
			Cli::new(COPY)
				.about("Copy one regular file into an absent name on Linux.")
				.after_help(OPERAND_ORDER)
				.arg(operand("SOURCE", 1))
				.arg(operand("TARGET", 2))
				.arg(directory_option(
					PROFILE,
					"Select the private signing profile.",
				))
				.arg(output_format()),
		)
		.subcommand(
			Cli::new(PLAN)
				.about("Plan one preserve-mode copy without changing the source or destination.")
				.after_help(OPERAND_ORDER)
				.arg(operand("SOURCE", 1))
				.arg(operand("DESTINATION", 2))
				.arg(directory_option(
					PROFILE,
					"Select the original private owner profile.",
				))
				.arg(path_option(
					OUTPUT,
					"FILE",
					"Write a new plan file under an existing owner-private bundle directory (mode 0700).",
				)),
		)
		.subcommand(
			Cli::new(MANIFEST)
				.about("Create a manifest of one regular file.")
				.disable_help_subcommand(true)
				.subcommand_required(true)
				.subcommand(
					Cli::new(CREATE)
						.about("Emit a content manifest for one regular file as JSON.")
						.arg(operand("PATH", 1)),
				),
		)
		.subcommand(
			Cli::new(VERIFY)
				.about("Verify one regular file against an existing manifest.")
				.after_help(OPERAND_ORDER)
				.arg(operand("PATH", 1))
				.arg(path_option(
					MANIFEST,
					"FILE",
					"Select the baseline manifest.",
				))
				.arg(output_format()),
		)
		.subcommand(recovery_commands())
		.subcommand(
			Cli::new(PROFILE)
				.about("Manage private Linux signing profiles.")
				.disable_help_subcommand(true)
				.subcommand_required(true)
				.subcommand(
					Cli::new(INIT)
						.about("Create a private signing profile.")
						.arg(operand("DIR", 1)),
				),
		);
	#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
	let cli = cli.subcommand(remote::get_subcommand());
	cli
}

fn recovery_commands() -> Cli {
	let cli = Cli::new(RECOVER)
		.about("Inspect or recover a retained Linux copy.")
		.disable_help_subcommand(true)
		.subcommand_required(true)
		.subcommand(recovery(INSPECT, "Inspect the current retained copy."))
		.subcommand(recovery(
			FINISH,
			"Finish a copy whose target was already published.",
		))
		.subcommand(source_recovery(
			RETRY,
			"Retry publication of a verified stage.",
		))
		.subcommand(source_recovery(RESUME, "Resume an interrupted copy."));
	#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
	let cli = cli.subcommand(remote::resume_subcommand());
	cli
}

fn operand(name: &'static str, position: usize) -> Arg {
	Arg::new(name)
		.index(position)
		.required(true)
		.value_parser(OsStringValueParser::new())
}

fn directory_option(name: &'static str, help: &'static str) -> Arg {
	path_option(name, "DIR", help)
}

fn path_option(name: &'static str, value_name: &'static str, help: &'static str) -> Arg {
	Arg::new(name)
		.long(name)
		.value_name(value_name)
		.value_parser(OsStringValueParser::new())
		.required(true)
		.help(help)
}

fn output_format() -> Arg {
	Arg::new(FORMAT)
		.long(FORMAT)
		.value_parser(PossibleValuesParser::new(["human", "json"]))
		.help("Select human-readable text (the default) or JSON.")
}

fn recovery(name: &'static str, help: &'static str) -> Cli {
	Cli::new(name)
		.about(help)
		.after_help(OPERAND_ORDER)
		.arg(operand("JOB", 1))
		.arg(directory_option(
			PROFILE,
			"Select the original signing profile.",
		))
		.arg(output_format())
}

fn source_recovery(name: &'static str, help: &'static str) -> Cli {
	recovery(name, help).arg(directory_option(
		SOURCE_ROOT,
		"Authorize the original source parent directory.",
	))
}

fn command_scope<'cli>(cli: &'cli Cli, args: &[OsString]) -> (&'cli Cli, usize) {
	let mut scope = cli;
	let mut count = 0;
	for arg in args {
		let Some(child) = arg.to_str().and_then(|name| scope.find_subcommand(name)) else {
			break;
		};
		scope = child;
		count += 1;
	}
	(scope, count)
}

fn frame_operands(
	scope: &Cli,
	prefix: usize,
	args: &mut Vec<OsString>,
) -> Result<(), &'static str> {
	let Some(first) = args.get(prefix) else {
		return Ok(());
	};
	if is_help(first) {
		return if args.len() == prefix + 1 {
			Ok(())
		} else {
			Err("request help by itself or use -- before a path named like a help flag")
		};
	}
	let operand_count = scope.get_positionals().count();
	if operand_count == 0 {
		return Ok(());
	}
	if first == "--" {
		args.remove(prefix);
	} else if scope.get_name() != DIFF && first.as_encoded_bytes().starts_with(b"-") {
		return Err("use -- before a path that starts with a dash");
	}
	let option_start = prefix + operand_count;
	if args.len() < option_start {
		return Ok(());
	}
	// Legacy syntax permits options after escaped, raw operands. Clap uses the
	// standard end-of-options delimiter, so give it the options before those operands.
	let mut options = args.split_off(option_start).into_iter().peekable();
	let operands = args.split_off(prefix);
	while let Some(mut option) = options.next() {
		if is_help(&option) {
			return Err("request help by itself or use -- before a path named like a help flag");
		}
		if is_path_option(scope.get_name(), &option)
			&& let Some(value) = options.next_if(|value| {
				let bytes = value.as_encoded_bytes();
				let legacy_profile =
					option == "--profile" && legacy_profile_framing(scope.get_name());
				bytes.starts_with(b"-") && (legacy_profile || !bytes.starts_with(b"--"))
			}) {
			// Bind a literal dash-prefixed path without allowing the injected
			// end-of-options marker to stand in for a missing grant.
			option.push("=");
			option.push(value);
		}
		args.push(option);
	}
	args.push("--".into());
	args.extend(operands);
	Ok(())
}

fn is_path_option(_command: &str, arg: &OsStr) -> bool {
	#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
	if remote::is_remote(_command) {
		return remote::is_path_option(arg);
	}
	arg == "--profile" || arg == "--source-root" || arg == "--manifest" || arg == "--output"
}

fn legacy_profile_framing(command: &str) -> bool {
	#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
	if remote::is_remote(command) {
		return false;
	}
	!matches!(command, RESUME | PLAN)
}

fn is_help(arg: &OsStr) -> bool {
	arg == "-h" || arg == "--help"
}

fn error_message(error: &clap::Error) -> &'static str {
	let arg = match error.get(ContextKind::InvalidArg) {
		Some(ContextValue::String(arg)) => arg.as_str(),
		_ => "",
	};
	match error.kind() {
		ErrorKind::ArgumentConflict => "an option was supplied more than once",
		ErrorKind::MissingRequiredArgument => "one or more required arguments were omitted",
		ErrorKind::UnknownArgument => "unexpected argument or option",
		ErrorKind::InvalidValue | ErrorKind::ValueValidation if arg == "--workers <N>" => {
			"--workers requires an integer from 1 to 16"
		}
		ErrorKind::InvalidValue | ErrorKind::ValueValidation => "an argument has an invalid value",
		_ => "invalid command invocation",
	}
}

fn invalid_invocation(scope: &mut Cli, message: &str) -> String {
	// Avoid echoing parser inputs, which can contain private paths and raw bytes.
	format!("exacopy: {message}\n{}\n", scope.render_usage())
}

fn typed_command(mut args: ArgMatches) -> Option<Command> {
	let (name, mut command) = args.remove_subcommand()?;
	match name.as_str() {
		DIFF => Some(Command::Diff(DiffCommand {
			left: path(&mut command, "LEFT")?,
			right: path(&mut command, "RIGHT")?,
			workers: command
				.get_one::<u8>(WORKERS)
				.and_then(|value| NonZeroUsize::new(usize::from(*value))),
			profile: if command.get_flag(MANAGED_MACOS) {
				DiffProfile::ManagedMacos
			} else if command.get_flag(LOCAL_NTFS) {
				DiffProfile::LocalNtfs
			} else {
				DiffProfile::Default
			},
			format: selected_format(&command),
		})),
		COPY => Some(Command::Copy(CopyCommand {
			source: path(&mut command, "SOURCE")?,
			target: path(&mut command, "TARGET")?,
			profile: path(&mut command, PROFILE)?,
			format: selected_format(&command),
		})),
		PLAN => Some(Command::Plan(PlanCommand {
			source: path(&mut command, "SOURCE")?,
			destination: path(&mut command, "DESTINATION")?,
			profile: path(&mut command, PROFILE)?,
			output: path(&mut command, OUTPUT)?,
		})),
		MANIFEST => {
			let (action, mut args) = command.remove_subcommand()?;
			if action != CREATE {
				return None;
			}
			Some(Command::ManifestCreate {
				path: path(&mut args, "PATH")?,
			})
		}
		VERIFY => Some(Command::Verify(VerifyCommand {
			path: path(&mut command, "PATH")?,
			manifest: path(&mut command, MANIFEST)?,
			format: selected_format(&command),
		})),
		#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
		remote::GET => remote::get(&mut command),
		RECOVER => recovery_command(command),
		PROFILE => {
			let (action, mut args) = command.remove_subcommand()?;
			if action != INIT {
				return None;
			}
			Some(Command::InitProfile(path(&mut args, "DIR")?))
		}
		_ => None,
	}
}

fn recovery_command(mut command: ArgMatches) -> Option<Command> {
	let (name, mut args) = command.remove_subcommand()?;
	let action = match name.as_str() {
		#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
		remote::REMOTE_RESUME => return remote::resume(&mut args),
		INSPECT => RecoveryAction::Inspect,
		FINISH => RecoveryAction::Finish,
		RETRY | RESUME => RecoveryAction::FromSource {
			action: if name == RETRY {
				SourceRecoveryAction::Retry
			} else {
				SourceRecoveryAction::Resume
			},
			source_root: path(&mut args, SOURCE_ROOT)?,
		},
		_ => return None,
	};
	Some(Command::Recover(RecoveryCommand {
		action,
		job: path(&mut args, "JOB")?,
		profile: path(&mut args, PROFILE)?,
		format: selected_format(&args),
	}))
}

fn path(args: &mut ArgMatches, name: &str) -> Option<PathBuf> {
	// Preserve empty and non-UTF-8 operands for operation-level path diagnostics.
	args.remove_one::<OsString>(name).map(PathBuf::from)
}

fn selected_format(args: &ArgMatches) -> Format {
	match args.get_one::<String>(FORMAT).map(String::as_str) {
		Some("json") => Format::Json,
		_ => Format::Human,
	}
}
