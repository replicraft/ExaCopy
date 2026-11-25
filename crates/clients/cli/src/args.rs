use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

pub(crate) const USAGE: &str = "Usage:\n  exacopy diff [--] LEFT RIGHT [--compare bytes] [--format human|json]\n  exacopy copy [--] SOURCE TARGET --profile DIR [--format human|json]\n  exacopy profile init [--] DIR";

pub(crate) enum Command {
	Help,
	Diff(DiffCommand),
	Copy(CopyCommand),
	InitProfile(PathBuf),
}

pub(crate) struct DiffCommand {
	pub(crate) left: PathBuf,
	pub(crate) right: PathBuf,
	pub(crate) format: Format,
}

pub(crate) struct CopyCommand {
	pub(crate) source: PathBuf,
	pub(crate) target: PathBuf,
	pub(crate) profile: PathBuf,
	pub(crate) format: Format,
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
		Some("profile") => parse_profile(args),
		_ => Err("expected a command"),
	}
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
	while let Some(flag) = args.next() {
		match flag.to_str() {
			Some("--format") if format.is_none() => format = Some(parse_format(args.next())?),
			Some("--compare") if !compare_selected => {
				if args.next().as_deref() != Some(OsStr::new("bytes")) {
					return Err("--compare requires bytes");
				}
				compare_selected = true;
			}
			Some("--format" | "--compare") => return Err("repeated diff option"),
			_ => return Err("unknown diff option"),
		}
	}

	Ok(Command::Diff(DiffCommand {
		left: left.into(),
		right: right.into(),
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
