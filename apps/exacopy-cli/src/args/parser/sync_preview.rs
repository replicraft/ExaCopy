use clap::{Arg, ArgAction, ArgMatches, Command as Cli};

use crate::args::{Command, SyncPreviewCommand};

use super::{OPERAND_ORDER, operand, path};

pub(super) const NAME: &str = "sync-preview";
const NO_HISTORY: &str = "no-history";
const PARENT: &str = "PARENT";
const LEFT: &str = "LEFT_ROOT";
const RIGHT: &str = "RIGHT_ROOT";
const SUBJECT: &str = "SUBJECT";

pub(super) fn definition() -> Cli {
	Cli::new(NAME)
		.about(
			"Preview one Linux synchronization subject without history. Reports live evidence as JSON.",
		)
		.after_help(OPERAND_ORDER)
		.arg(
			operand(PARENT, 1)
				.help("Absolute path to the common parent on a supported local mount."),
		)
		.arg(operand(LEFT, 2).help("Left direct child directory name."))
		.arg(operand(RIGHT, 3).help("Right direct child directory name."))
		.arg(operand(SUBJECT, 4).help("Exact basename in each directory."))
		.arg(
			Arg::new(NO_HISTORY)
				.long(NO_HISTORY)
				.required(true)
				.action(ArgAction::SetTrue)
				.help("Explicitly select an uninitialized baseline."),
		)
}

pub(super) fn command(args: &mut ArgMatches) -> Option<Command> {
	if !args.get_flag(NO_HISTORY) {
		return None;
	}
	Some(Command::SyncPreview(SyncPreviewCommand {
		parent: path(args, PARENT)?,
		roots: [path(args, LEFT)?, path(args, RIGHT)?],
		subject: path(args, SUBJECT)?,
	}))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn accepts_one_explicit_preview_selection() {
		use std::ffi::OsString;

		let operands = [NAME, "/work", "left", "right", "file"];
		assert!(crate::args::parse(operands.into_iter().map(OsString::from)).is_err());
		let command = crate::args::parse(
			operands
				.into_iter()
				.chain(["--no-history"])
				.map(OsString::from),
		)
		.unwrap();
		let Command::SyncPreview(command) = command else {
			panic!("expected a typed sync preview command");
		};
		assert_eq!(
			command.roots,
			["left", "right"].map(std::path::PathBuf::from)
		);
	}
}
