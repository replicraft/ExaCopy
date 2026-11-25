use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

pub(crate) const USAGE: &str =
	"Usage: exacopy diff [--] LEFT RIGHT [--compare bytes] [--format human|json]";

pub(crate) enum Command {
	Help,
	Diff(DiffCommand),
}

pub(crate) struct DiffCommand {
	pub(crate) left: PathBuf,
	pub(crate) right: PathBuf,
	pub(crate) format: Format,
}

#[derive(Clone, Copy)]
pub(crate) enum Format {
	Human,
	Json,
}

pub(crate) fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Command, &'static str> {
	match args.next().as_deref().and_then(OsStr::to_str) {
		Some("--help" | "-h") if args.next().is_none() => return Ok(Command::Help),
		Some("diff") => {}
		_ => return Err("expected the diff command"),
	}

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
			Some("--format") if format.is_none() => {
				format = Some(match args.next().as_deref().and_then(OsStr::to_str) {
					Some("human") => Format::Human,
					Some("json") => Format::Json,
					_ => return Err("--format requires human or json"),
				});
			}
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
