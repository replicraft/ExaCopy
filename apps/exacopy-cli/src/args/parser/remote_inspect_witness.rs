use std::ffi::OsStr;

use clap::{ArgMatches, Command as Cli};

use super::{OPERAND_ORDER, operand, output_format, path, path_option, selected_format};

use crate::args::{Command, RemoteInspectWitnessCommand};

pub(super) const NAME: &str = "remote-inspect-witness";
const ARCHIVE: &str = "selection-report";
const QUALIFICATION: &str = "destination-qualification";
const QUALIFICATION_TRUST: &str = "qualification-trust";
const CONTINUATION: &str = "continuation-qualification";
const CONTINUATION_TRUST: &str = "continuation-trust";

pub(super) fn definition() -> Cli {
	Cli::new(NAME)
		.about("Verify a committed witnessed remote receipt using a protected archived selection.")
		.after_help(OPERAND_ORDER)
		.arg(operand("JOB", 1))
		.arg(path_option(
			ARCHIVE,
			"FILE",
			"Select the protected successful witness report.",
		))
		.arg(path_option(
			QUALIFICATION,
			"FILE",
			"Select the signed destination qualification.",
		))
		.arg(path_option(
			QUALIFICATION_TRUST,
			"FILE",
			"Select the independently protected destination trust.",
		))
		.arg(path_option(
			CONTINUATION,
			"FILE",
			"Select the signed witnessed continuation qualification.",
		))
		.arg(path_option(
			CONTINUATION_TRUST,
			"FILE",
			"Select the independently protected witnessed trust.",
		))
		.arg(output_format())
}

pub(super) fn is_path_option(arg: &OsStr) -> bool {
	arg == "--selection-report"
		|| arg == "--destination-qualification"
		|| arg == "--qualification-trust"
		|| arg == "--continuation-qualification"
		|| arg == "--continuation-trust"
}

pub(super) fn command(args: &mut ArgMatches) -> Option<Command> {
	Some(Command::RemoteInspectWitness(RemoteInspectWitnessCommand {
		job: path(args, "JOB")?,
		selection_report: path(args, ARCHIVE)?,
		destination_qualification: path(args, QUALIFICATION)?,
		qualification_trust: path(args, QUALIFICATION_TRUST)?,
		continuation_qualification: path(args, CONTINUATION)?,
		continuation_trust: path(args, CONTINUATION_TRUST)?,
		format: selected_format(args),
	}))
}

#[cfg(test)]
mod tests {
	use std::ffi::OsString;
	use std::os::unix::ffi::OsStringExt as _;
	use std::path::{Path, PathBuf};

	use crate::args::{Command, Format, parse};

	use super::NAME;

	#[test]
	fn witness_inspection_accepts_only_explicit_read_only_inputs() {
		let job = OsString::from_vec(b"-job-\xff".to_vec());
		let archive = OsString::from_vec(b"-archive-\xfe".to_vec());
		let invocation = ["recover".into(), NAME.into(), "--".into(), job.clone()];
		let options = [
			("--selection-report", archive.clone()),
			("--destination-qualification", "op1.cbor".into()),
			("--qualification-trust", "op1.json".into()),
			("--continuation-qualification", "op2.cbor".into()),
			("--continuation-trust", "op2.json".into()),
		];
		let input = |omit| {
			invocation.iter().cloned().chain(
				options
					.iter()
					.enumerate()
					.filter(move |(index, _)| Some(*index) != omit)
					.flat_map(|(_, (flag, value))| [OsString::from(*flag), value.clone()]),
			)
		};
		let Ok(Command::RemoteInspectWitness(parsed)) =
			parse(input(None).chain(["--format".into(), "json".into()]))
		else {
			panic!("expected the read-only witness inspection");
		};
		assert_eq!(parsed.job, PathBuf::from(job));
		assert_eq!(parsed.selection_report, PathBuf::from(archive));
		assert_eq!(parsed.destination_qualification, Path::new("op1.cbor"));
		assert_eq!(parsed.qualification_trust, Path::new("op1.json"));
		assert_eq!(parsed.continuation_qualification, Path::new("op2.cbor"));
		assert_eq!(parsed.continuation_trust, Path::new("op2.json"));
		assert!(matches!(parsed.format, Format::Json));

		for index in 0..options.len() {
			assert!(parse(input(Some(index))).is_err());
		}
		for credential in ["--profile", "--ssh-profile", "--grant"] {
			assert!(parse(input(None).chain([credential.into(), "private-value".into()])).is_err());
		}
	}
}
