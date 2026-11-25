use std::ffi::{OsStr, OsString};
use std::num::NonZeroUsize;
use std::path::PathBuf;

pub(crate) const USAGE: &str = "Usage:\n  exacopy diff [--] LEFT RIGHT [--compare bytes] [--workers N] [--format human|json]\n  exacopy copy [--] SOURCE TARGET --profile DIR [--format human|json]\n  exacopy recover inspect|finish [--] JOB --profile DIR [--format human|json]\n  exacopy recover retry [--] JOB --source-root DIR --profile DIR [--format human|json]\n  exacopy recover resume [--] JOB --source-root DIR --profile DIR [--format human|json]\n  exacopy profile init [--] DIR";

const MAX_DIFF_WORKERS: usize = 16;

#[cfg(target_os = "linux")]
const _: () = assert!(
	MAX_DIFF_WORKERS == exacopy_diff::linux::MAX_WORKERS,
	"the CLI worker limit must match the comparison engine"
);

pub(crate) enum Command {
	Help,
	Diff(DiffCommand),
	Copy(CopyCommand),
	Recover(RecoveryCommand),
	InitProfile(PathBuf),
}

pub(crate) struct DiffCommand {
	pub(crate) left: PathBuf,
	pub(crate) right: PathBuf,
	pub(crate) workers: Option<NonZeroUsize>,
	pub(crate) format: Format,
}

pub(crate) struct CopyCommand {
	pub(crate) source: PathBuf,
	pub(crate) target: PathBuf,
	pub(crate) profile: PathBuf,
	pub(crate) format: Format,
}

pub(crate) struct RecoveryCommand {
	pub(crate) action: RecoveryAction,
	pub(crate) job: PathBuf,
	pub(crate) profile: PathBuf,
	pub(crate) format: Format,
}

pub(crate) enum RecoveryAction {
	Inspect,
	Finish,
	FromSource {
		action: SourceRecoveryAction,
		source_root: PathBuf,
	},
}

#[derive(Clone, Copy)]
pub(crate) enum SourceRecoveryAction {
	Retry,
	Resume,
}

enum RecoveryVerb {
	Inspect,
	Finish,
	FromSource(SourceRecoveryAction),
}

#[derive(Clone, Copy)]
pub(crate) enum Format {
	Human,
	Json,
}

pub(crate) fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Command, &'static str> {
	match args.next().as_deref().and_then(OsStr::to_str) {
		Some("--help" | "-h") if args.next().is_none() => Ok(Command::Help),
		Some("diff") => parse_diff(args),
		Some("copy") => parse_copy(args),
		Some("recover") => parse_recover(args),
		Some("profile") => parse_profile(args),
		_ => Err("expected a command"),
	}
}

fn parse_recover(mut args: impl Iterator<Item = OsString>) -> Result<Command, &'static str> {
	let action = match args.next().as_deref().and_then(OsStr::to_str) {
		Some("--help" | "-h") if args.next().is_none() => return Ok(Command::Help),
		Some("inspect") => RecoveryVerb::Inspect,
		Some("finish") => RecoveryVerb::Finish,
		Some("retry") => RecoveryVerb::FromSource(SourceRecoveryAction::Retry),
		Some("resume") => RecoveryVerb::FromSource(SourceRecoveryAction::Resume),
		_ => {
			return Err(
				"expected recover inspect, recover finish, recover retry, or recover resume",
			);
		}
	};
	let first = args.next().ok_or("recovery requires a job path")?;
	let job = match first.to_str() {
		Some("--help" | "-h") if args.next().is_none() => return Ok(Command::Help),
		Some("--") => args.next().ok_or("recovery requires a job path")?,
		_ if first.as_encoded_bytes().starts_with(b"-") => {
			return Err("use -- before a path that starts with a dash");
		}
		_ => first,
	};
	let mut profile = None;
	let mut source_root = None;
	let mut format = None;
	while let Some(flag) = args.next() {
		match flag.to_str() {
			Some("--profile") if profile.is_none() => {
				profile = Some(
					args.next()
						.filter(|value| {
							!matches!(
								action,
								RecoveryVerb::FromSource(SourceRecoveryAction::Resume)
							) || !value.as_encoded_bytes().starts_with(b"--")
						})
						.ok_or("--profile requires a directory")?,
				);
			}
			Some("--format") if format.is_none() => format = Some(parse_format(args.next())?),
			Some("--source-root") if !matches!(action, RecoveryVerb::FromSource(_)) => {
				return Err("--source-root requires recover retry or recover resume");
			}
			Some("--source-root") if source_root.is_none() => {
				source_root = Some(
					args.next()
						.filter(|value| !value.as_encoded_bytes().starts_with(b"--"))
						.ok_or("--source-root requires a directory")?,
				);
			}
			Some("--profile" | "--format" | "--source-root") => {
				return Err("repeated recovery option");
			}
			_ => return Err("unknown recovery option"),
		}
	}
	Ok(Command::Recover(RecoveryCommand {
		action: match action {
			RecoveryVerb::Inspect => RecoveryAction::Inspect,
			RecoveryVerb::Finish => RecoveryAction::Finish,
			RecoveryVerb::FromSource(action) => RecoveryAction::FromSource {
				action,
				source_root: source_root
					.ok_or(match action {
						SourceRecoveryAction::Retry => {
							"recover retry requires an explicit --source-root DIR"
						}
						SourceRecoveryAction::Resume => {
							"recover resume requires an explicit --source-root DIR"
						}
					})?
					.into(),
			},
		},
		job: job.into(),
		profile: profile
			.ok_or("recovery requires an explicit --profile DIR")?
			.into(),
		format: format.unwrap_or(Format::Human),
	}))
}

fn parse_diff(mut args: impl Iterator<Item = OsString>) -> Result<Command, &'static str> {
	let first = args.next().ok_or("expected left and right paths")?;
	let left = match first.to_str() {
		Some("--help" | "-h") if args.next().is_none() => return Ok(Command::Help),
		Some("--help" | "-h") => return Err("use -- before a path that starts with a dash"),
		Some("--") => args.next().ok_or("expected left and right paths")?,
		_ => first,
	};
	let right = args.next().ok_or("expected a right path")?;

	let mut format = None;
	let mut compare_selected = false;
	let mut workers = None;
	while let Some(flag) = args.next() {
		match flag.to_str() {
			Some("--format") if format.is_none() => format = Some(parse_format(args.next())?),
			Some("--compare") if !compare_selected => {
				if args.next().as_deref() != Some(OsStr::new("bytes")) {
					return Err("--compare requires bytes");
				}
				compare_selected = true;
			}
			Some("--workers") if workers.is_none() => workers = Some(parse_workers(args.next())?),
			Some("--format" | "--compare" | "--workers") => {
				return Err("repeated diff option");
			}
			_ => return Err("unknown diff option"),
		}
	}

	Ok(Command::Diff(DiffCommand {
		left: left.into(),
		right: right.into(),
		workers,
		format: format.unwrap_or(Format::Human),
	}))
}

fn parse_copy(mut args: impl Iterator<Item = OsString>) -> Result<Command, &'static str> {
	let first = args.next().ok_or("expected source and target paths")?;
	let source = match first.to_str() {
		Some("--help" | "-h") if args.next().is_none() => return Ok(Command::Help),
		Some("--") => args.next().ok_or("expected source and target paths")?,
		_ if first.as_encoded_bytes().starts_with(b"-") => {
			return Err("use -- before a path that starts with a dash");
		}
		_ => first,
	};
	let target = args.next().ok_or("expected a target path")?;
	let mut profile = None;
	let mut format = None;
	while let Some(flag) = args.next() {
		match flag.to_str() {
			Some("--profile") if profile.is_none() => {
				profile = Some(args.next().ok_or("--profile requires a directory")?);
			}
			Some("--format") if format.is_none() => format = Some(parse_format(args.next())?),
			Some("--profile" | "--format") => return Err("repeated copy option"),
			_ => return Err("unknown copy option"),
		}
	}
	Ok(Command::Copy(CopyCommand {
		source: source.into(),
		target: target.into(),
		profile: profile
			.ok_or("copy requires an explicit --profile DIR")?
			.into(),
		format: format.unwrap_or(Format::Human),
	}))
}

fn parse_profile(mut args: impl Iterator<Item = OsString>) -> Result<Command, &'static str> {
	let subcommand = args.next();
	match subcommand.as_deref().and_then(OsStr::to_str) {
		Some("--help" | "-h") if args.next().is_none() => return Ok(Command::Help),
		Some("init") => {}
		_ => return Err("expected profile init DIR"),
	}
	let first = args.next().ok_or("profile init requires a directory")?;
	let directory = match first.to_str() {
		Some("--help" | "-h") if args.next().is_none() => return Ok(Command::Help),
		Some("--") => args.next().ok_or("profile init requires a directory")?,
		_ if first.as_encoded_bytes().starts_with(b"-") => {
			return Err("use -- before a path that starts with a dash");
		}
		_ => first,
	};
	if args.next().is_some() {
		return Err("profile init accepts one directory");
	}
	Ok(Command::InitProfile(directory.into()))
}

fn parse_format(value: Option<OsString>) -> Result<Format, &'static str> {
	match value.as_deref().and_then(OsStr::to_str) {
		Some("human") => Ok(Format::Human),
		Some("json") => Ok(Format::Json),
		_ => Err("--format requires human or json"),
	}
}

fn parse_workers(value: Option<OsString>) -> Result<NonZeroUsize, &'static str> {
	value
		.as_deref()
		.and_then(OsStr::to_str)
		.and_then(|value| value.parse::<NonZeroUsize>().ok())
		.filter(|workers| workers.get() <= MAX_DIFF_WORKERS)
		.ok_or("--workers requires an integer from 1 to 16")
}
