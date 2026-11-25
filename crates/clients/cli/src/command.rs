use std::ffi::OsString;
use std::io::{self, Write as _};
use std::process::ExitCode;

use crate::args::{self, Command, DiffCommand, Format, USAGE};
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
	let Command::Diff(diff) = command else {
		return match writeln!(stdout, "{USAGE}").and_then(|()| stdout.flush()) {
			Ok(()) => ExitCode::SUCCESS,
			Err(_) => ExitCode::from(INCONCLUSIVE),
		};
	};

	let outcome = compare(&diff);
	let code = outcome.exit_code();
	let result = match diff.format {
		Format::Human => outcome.write_human(&mut stdout, &mut stderr),
		Format::Json => Report::new(outcome).write_json(&mut stdout),
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
