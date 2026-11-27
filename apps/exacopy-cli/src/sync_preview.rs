use std::io::Write;

use serde_json::{Value, json};

use crate::args::SyncPreviewCommand;
use crate::report::INCONCLUSIVE;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(target_os = "linux", feature = "experimental-linux-managed-sync"))]
pub(crate) mod managed_ack;
#[cfg(all(target_os = "linux", feature = "experimental-linux-managed-sync"))]
pub(crate) mod managed_command;
#[cfg(all(target_os = "linux", feature = "experimental-linux-managed-sync"))]
pub(crate) mod managed_policy;
#[cfg(all(target_os = "linux", feature = "experimental-linux-managed-sync"))]
mod managed_report;

pub(crate) fn run(
	command: &SyncPreviewCommand,
	stdout: &mut impl Write,
	stderr: &mut impl Write,
) -> u8 {
	let (report, exit) = preview(command);
	if write_report(&report, stdout).is_err() {
		let _ = writeln!(stderr, "exacopy: could not write the sync preview");
		return INCONCLUSIVE;
	}
	exit
}

fn write_report(report: &Value, stdout: &mut impl Write) -> std::io::Result<()> {
	serde_json::to_writer(&mut *stdout, report)?;
	writeln!(stdout)?;
	stdout.flush()
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
