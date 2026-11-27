use clap::builder::ValueParser;
use clap::{Arg, ArgMatches, Command as Cli};

use crate::args::{Command, PublicStageInspectCommand};

use super::{OPERAND_ORDER, operand, output_format, path, selected_format};

pub(super) const NAME: &str = "inspect-public-stage";
const OWNER_KEY: &str = "owner-key";

pub(super) fn definition() -> Cli {
	Cli::new(NAME)
		.about("Inspect retained public-stage evidence without changing it.")
		.after_help(OPERAND_ORDER)
		.arg(operand("JOB", 1))
		.arg(
			Arg::new(OWNER_KEY)
				.long(OWNER_KEY)
				.value_name("HEX")
				.value_parser(ValueParser::new(owner_key))
				.required(true)
				.help("Independently selected Ed25519 public owner key in lowercase hex."),
		)
		.arg(output_format())
}

pub(super) fn command(args: &mut ArgMatches) -> Option<Command> {
	Some(Command::InspectPublicStage(PublicStageInspectCommand {
		job: path(args, "JOB")?,
		owner_key: args.remove_one(OWNER_KEY)?,
		format: selected_format(args),
	}))
}

fn owner_key(value: &str) -> Result<[u8; 32], &'static str> {
	const INVALID: &str = "expected exactly 64 lowercase hexadecimal digits";
	if value.len() != 64
		|| !value
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
	{
		return Err(INVALID);
	}
	let mut key = [0; 32];
	for (pair, output) in value.as_bytes().as_chunks::<2>().0.iter().zip(&mut key) {
		let pair = str::from_utf8(pair).map_err(|_| INVALID)?;
		*output = u8::from_str_radix(pair, 16).map_err(|_| INVALID)?;
	}
	Ok(key)
}
