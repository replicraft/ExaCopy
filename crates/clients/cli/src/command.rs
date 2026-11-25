use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use crate::args::{self, Command, CopyCommand, DiffCommand, Format, RecoveryCommand, USAGE};
use crate::copy_report::CopyOutcome;
use crate::recovery_report::RecoveryOutcome;
use crate::report::{INCONCLUSIVE, Outcome, Report};

pub(crate) fn run(args: impl Iterator<Item = OsString>) -> ExitCode {
	let mut stdout = io::stdout().lock();
	let mut stderr = io::stderr().lock();
	let command = match args::parse(args) {
		Ok(command) => command,
		Err(error) => {
			let _ = writeln!(stderr, "exacopy: {error}\n{USAGE}");
			return ExitCode::from(INCONCLUSIVE);
		}
	};
	match command {
		Command::Help => match writeln!(stdout, "{USAGE}").and_then(|()| stdout.flush()) {
			Ok(()) => ExitCode::SUCCESS,
			Err(_) => ExitCode::from(INCONCLUSIVE),
		},
		Command::Diff(diff) => run_diff(diff, &mut stdout, &mut stderr),
		Command::Copy(copy) => {
			let outcome = execute_copy(&copy);
			let code = match outcome.write(copy.format, &mut stdout, &mut stderr) {
				Ok(()) => outcome.exit_code(),
				Err(error) => outcome.failed_output(&mut stderr, &error),
			};
			ExitCode::from(code)
		}
		Command::InitProfile(path) => ExitCode::from(init_profile(&path, &mut stderr)),
		Command::Recover(recovery) => {
			let outcome = execute_recovery(&recovery);
			match outcome.write(recovery.format, &mut stdout, &mut stderr) {
				Ok(()) => ExitCode::from(outcome.exit_code()),
				Err(error) => {
					let _ = writeln!(stderr, "exacopy: could not write recovery result ({error})");
					ExitCode::from(4)
				}
			}
		}
	}
}

#[cfg(target_os = "linux")]
fn execute_recovery(command: &RecoveryCommand) -> RecoveryOutcome {
	crate::recovery::execute(command)
}

#[cfg(not(target_os = "linux"))]
fn execute_recovery(command: &RecoveryCommand) -> RecoveryOutcome {
	let _ = (&command.job, &command.profile);
	if let crate::args::RecoveryAction::Retry { source_root } = &command.action {
		let _ = source_root;
	}
	RecoveryOutcome::failure(
		crate::copy_report::ErrorKind::Unsupported,
		"local recovery requires Linux",
	)
}

fn run_diff(diff: DiffCommand, stdout: &mut impl Write, stderr: &mut impl Write) -> ExitCode {
	let outcome = compare(&diff);
	let code = outcome.exit_code();
	let result = match diff.format {
		Format::Human => outcome.write_human(stdout, &mut *stderr),
		Format::Json => Report::new(outcome).write_json(stdout),
	};
	if let Err(error) = result {
		let _ = writeln!(stderr, "exacopy: could not write the diff result ({error})");
		return ExitCode::from(INCONCLUSIVE);
	}
	code
}

#[cfg(target_os = "linux")]
fn compare(diff: &DiffCommand) -> Outcome {
	crate::linux::compare(&diff.left, &diff.right)
}

#[cfg(not(target_os = "linux"))]
fn compare(diff: &DiffCommand) -> Outcome {
	let _ = (&diff.left, &diff.right);
	Outcome::Inconclusive {
		error: crate::report::Failure {
			code: crate::report::ErrorCode::UnsupportedPlatform,
			message: "local byte comparison requires Linux".into(),
		},
	}
}

#[cfg(target_os = "linux")]
fn execute_copy(command: &CopyCommand) -> CopyOutcome {
	crate::copy::execute(command)
}

#[cfg(not(target_os = "linux"))]
fn execute_copy(command: &CopyCommand) -> CopyOutcome {
	use crate::copy_report::{CopyFailure, ErrorKind};

	let _ = (&command.source, &command.target, &command.profile);
	CopyOutcome::Failed {
		error: CopyFailure::new(ErrorKind::Unsupported, "local copy requires Linux"),
	}
}

#[cfg(target_os = "linux")]
fn init_profile(path: &Path, stderr: &mut impl Write) -> u8 {
	match crate::profile::init(path) {
		Ok(()) => 0,
		Err(error) => {
			let _ = writeln!(
				stderr,
				"exacopy: could not initialize the profile ({error})"
			);
			error.init_exit_code()
		}
	}
}

#[cfg(not(target_os = "linux"))]
fn init_profile(_: &Path, stderr: &mut impl Write) -> u8 {
	let _ = writeln!(stderr, "exacopy: local profiles require Linux");
	6
}
