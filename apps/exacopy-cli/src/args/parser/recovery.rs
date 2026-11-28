use clap::{ArgMatches, Command as Cli};

#[cfg(all(target_os = "linux", feature = "experimental-linux-public-apply"))]
use super::public_stage;
#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
use super::remote;
#[cfg(all(target_os = "linux", feature = "experimental-verified-prefix-resume"))]
use super::remote_inspect_witness;
use super::{
	OPERAND_ORDER, PROFILE, RECOVER, RESUME, SOURCE_ROOT, directory_option, operand, output_format,
	path, selected_format,
};
use crate::args::{Command, RecoveryAction, RecoveryCommand, SourceRecoveryAction};

#[cfg(all(target_os = "macos", feature = "experimental-apfs-copy"))]
mod apfs;

const INSPECT: &str = "inspect";
const FINISH: &str = "finish";
const RETRY: &str = "retry";

pub(super) fn definition() -> Cli {
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
	#[cfg(all(target_os = "linux", feature = "experimental-linux-public-apply"))]
	let cli = cli.subcommand(public_stage::definition());
	#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
	let cli = cli.subcommand(remote::resume_subcommand());
	#[cfg(all(target_os = "linux", feature = "experimental-verified-prefix-resume"))]
	let cli = cli.subcommand(remote_inspect_witness::definition());
	#[cfg(all(target_os = "macos", feature = "experimental-apfs-copy"))]
	let cli = cli
		.about("Inspect a retained managed APFS job.")
		.subcommand(apfs::definition());
	cli
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

pub(super) fn command(mut command: ArgMatches) -> Option<Command> {
	let (name, mut args) = command.remove_subcommand()?;
	let action = match name.as_str() {
		#[cfg(all(target_os = "macos", feature = "experimental-apfs-copy"))]
		apfs::NAME => return apfs::command(&mut args),
		#[cfg(all(target_os = "linux", feature = "experimental-ssh-capture"))]
		remote::REMOTE_RESUME => return remote::resume(&mut args),
		#[cfg(all(target_os = "linux", feature = "experimental-verified-prefix-resume"))]
		remote_inspect_witness::NAME => return remote_inspect_witness::command(&mut args),
		#[cfg(all(target_os = "linux", feature = "experimental-linux-public-apply"))]
		public_stage::NAME => return public_stage::command(&mut args),
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

#[cfg(all(target_os = "macos", feature = "experimental-apfs-copy"))]
pub(super) fn is_apfs_path_option(command: &str, arg: &std::ffi::OsStr) -> bool {
	command == apfs::NAME && arg == "--stage-container"
}
