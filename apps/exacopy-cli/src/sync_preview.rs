use std::io::Write;

use serde_json::{Value, json};

use crate::args::SyncPreviewCommand;
use crate::report::INCONCLUSIVE;

#[cfg(target_os = "linux")]
mod linux;

pub(crate) fn run(
	command: &SyncPreviewCommand,
	stdout: &mut impl Write,
	stderr: &mut impl Write,
) -> u8 {
	let (report, exit) = preview(command);
	let output = serde_json::to_writer(&mut *stdout, &report)
		.map_err(std::io::Error::other)
		.and_then(|()| writeln!(stdout))
		.and_then(|()| stdout.flush());
	if output.is_err() {
		let _ = writeln!(stderr, "exacopy: could not write the sync preview");
		return INCONCLUSIVE;
	}
	exit
}

#[cfg(target_os = "linux")]
use linux::preview;

#[cfg(not(target_os = "linux"))]
fn preview(command: &SyncPreviewCommand) -> (Value, u8) {
	let _ = (&command.parent, &command.roots, &command.subject);
	blocked("unsupported_platform", None)
}

fn blocked(reason: &str, side: Option<&str>) -> (Value, u8) {
	let mut report = json!({
		"status": "blocked",
		"reason": reason,
		"history": "none",
		"scope": "one_subject",
		"scope_complete": false,
	});
	if let Some(side) = side {
		report["side"] = json!(side);
	}
	(report, INCONCLUSIVE)
}
