use std::fmt::Write as _;
use std::io::Write;

use ed25519_dalek::VerifyingKey;
use exacopy_journal::frame::ChainHead;
use exacopy_journal::windows_bootstrap::{WindowsBootstrapSelection, job_directory_name};
use exacopy_journal::{JournalJobId, OwnerDigest};
use serde::Serialize;

use crate::args::InspectWindowsBootstrapCommand;
use crate::assembly::windows::{WindowsBootstrapRefusal, inspect_bootstrap};

pub(crate) fn run(
	command: &InspectWindowsBootstrapCommand,
	stdout: &mut impl Write,
	stderr: &mut impl Write,
) -> u8 {
	let outcome = observe(command);
	let exit = outcome.exit_code();
	let report = Report {
		schema: "exacopy.cli.windows_bootstrap_inspection",
		schema_version: "1.0",
		authority: "none",
		outcome,
	};
	if report.write(stdout).is_err() {
		let _ = writeln!(
			stderr,
			"exacopy: could not write the Windows bootstrap inspection result"
		);
		return 4;
	}
	exit
}

fn observe(command: &InspectWindowsBootstrapCommand) -> Outcome {
	let Ok(key) = VerifyingKey::from_bytes(&command.owner_key) else {
		return Outcome::Refused {
			reason: Reason::Selection,
		};
	};
	let selection = WindowsBootstrapSelection {
		profile: command.profile,
		job: command.job,
		key: &key,
		root: command.root_identity,
	};
	match inspect_bootstrap(&command.root, &selection) {
		Ok(observed) => {
			let boundary = observed.boundary();
			Outcome::historical(
				command.job,
				observed.owner_digest(),
				boundary.head(),
				boundary.end_offset(),
			)
		}
		Err(refusal) => Outcome::Refused {
			reason: match refusal {
				WindowsBootstrapRefusal::UntrustedKey => Reason::Selection,
				WindowsBootstrapRefusal::InvalidLayout | WindowsBootstrapRefusal::Custody(_) => {
					Reason::Custody
				}
				WindowsBootstrapRefusal::History(_) => Reason::History,
			},
		},
	}
}

#[derive(Serialize)]
struct Report {
	schema: &'static str,
	schema_version: &'static str,
	authority: &'static str,
	#[serde(flatten)]
	outcome: Outcome,
}

impl Report {
	fn write(&self, stdout: &mut impl Write) -> std::io::Result<()> {
		serde_json::to_writer(&mut *stdout, self)?;
		stdout.write_all(b"\n")?;
		stdout.flush()
	}
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Outcome {
	Observed {
		job_id: String,
		owner_blake3: String,
		historical_head_blake3: String,
		journal_sequence: String,
		first_segment_extent: String,
	},
	Refused {
		reason: Reason,
	},
}

impl Outcome {
	fn historical(job: JournalJobId, owner: OwnerDigest, head: ChainHead, extent: u64) -> Self {
		let job = job_directory_name(job);
		Self::Observed {
			job_id: String::from_utf16_lossy(&job[b".exacopy-".len()..]),
			owner_blake3: hex(owner.as_bytes()),
			historical_head_blake3: hex(&head.digest()),
			journal_sequence: head.sequence().to_string(),
			first_segment_extent: extent.to_string(),
		}
	}

	const fn exit_code(&self) -> u8 {
		match self {
			Self::Observed { .. } => 0,
			Self::Refused {
				reason: Reason::Selection,
			} => 2,
			Self::Refused { .. } => 9,
		}
	}
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Reason {
	Selection,
	Custody,
	History,
}

fn hex(bytes: &[u8; 32]) -> String {
	let mut text = String::with_capacity(64);
	for byte in bytes {
		write!(text, "{byte:02x}").expect("hex formatting into a string");
	}
	text
}

#[cfg(test)]
mod tests;
