use std::io::{self, Write};

use exacopy_platform::macos::ManagedObjectIdentity;
use exacopy_platform::macos::staging::jobs::RecoveryFileObservation;
use serde::Serialize;

use crate::args::Format;
use crate::assembly::macos::inspection::{DarwinJobInspection, DarwinReceiptArtifact};
use crate::assembly::macos::replay::{DarwinJournalTail, DarwinReplayStatus};

#[derive(Clone, Copy, Serialize)]
pub(super) enum Failure {
	#[serde(rename = "E_APFS_SELECTION")]
	Selection,
	#[serde(rename = "E_APFS_CUSTODY")]
	Custody,
	#[serde(rename = "E_APFS_BINDING")]
	Binding,
	#[serde(rename = "E_APFS_HISTORY")]
	History,
}

impl Failure {
	const fn message(self) -> &'static str {
		match self {
			Self::Selection => "the requested APFS inspection selection is invalid",
			Self::Custody => "the selected managed APFS job could not be held and observed",
			Self::Binding => "the selected APFS job or held destination differs from the plan",
			Self::History => "the selected APFS job history could not be authenticated or verified",
		}
	}
}

#[derive(Serialize)]
pub(super) struct Report {
	schema: &'static str,
	schema_version: &'static str,
	#[serde(skip)]
	exit_code: u8,
	#[serde(flatten)]
	outcome: Outcome,
}

#[derive(Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum Outcome {
	Inspected(Box<Observation>),
	Refused {
		code: Failure,
		message: &'static str,
	},
}

#[derive(Serialize)]
struct Observation {
	historical_status: &'static str,
	journal_sequence: String,
	journal_offset: String,
	journal_head_digest: String,
	journal_tail: &'static str,
	#[serde(skip_serializing_if = "Option::is_none")]
	torn_bytes: Option<String>,
	receipt: Receipt,
	stage_directory: Option<Identity>,
	stage: Option<Entry>,
	target: Option<Entry>,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Receipt {
	Missing,
	PresentUncommitted,
	MatchesHistoricalCommitment { digest: String },
}

#[derive(Serialize)]
struct Entry {
	identity: Identity,
	length: String,
}

#[derive(Serialize)]
struct Identity {
	device: i32,
	physical_fsid: [u32; 2],
	inode: String,
	generation: Option<u32>,
	birth_seconds: String,
	birth_nanoseconds: u32,
}

impl Report {
	pub(super) fn observed(inspection: DarwinJobInspection) -> Self {
		let status = inspection.replay.status();
		let boundary = inspection.replay.boundary();
		let tail = inspection.replay.tail();
		let exit_code = observation_exit_code(status, tail, inspection.receipt);
		let observed = Observation {
			historical_status: match status {
				DarwinReplayStatus::Incomplete => "incomplete",
				DarwinReplayStatus::Conflict => "conflict",
				DarwinReplayStatus::Uncertain => "uncertain",
				DarwinReplayStatus::PublishedIncomplete => "published_incomplete",
				DarwinReplayStatus::Complete => "complete",
			},
			journal_sequence: boundary.head.sequence().to_string(),
			journal_offset: boundary.offset.to_string(),
			journal_head_digest: hex(&boundary.head.digest()),
			journal_tail: match tail {
				DarwinJournalTail::Clean => "clean",
				DarwinJournalTail::Torn { .. } => "torn",
			},
			torn_bytes: match tail {
				DarwinJournalTail::Clean => None,
				DarwinJournalTail::Torn { bytes_read } => Some(bytes_read.to_string()),
			},
			receipt: match inspection.receipt {
				DarwinReceiptArtifact::Missing => Receipt::Missing,
				DarwinReceiptArtifact::PresentUncommitted => Receipt::PresentUncommitted,
				DarwinReceiptArtifact::MatchesCommitment(digest) => {
					Receipt::MatchesHistoricalCommitment {
						digest: hex(digest.as_bytes()),
					}
				}
			},
			stage_directory: inspection.stage_directory.map(Into::into),
			stage: inspection.stage.map(Into::into),
			target: inspection.target.map(Into::into),
		};
		Self::new(exit_code, Outcome::Inspected(Box::new(observed)))
	}

	pub(super) fn refused(code: Failure) -> Self {
		let exit_code = match code {
			Failure::Selection => 2,
			Failure::Custody | Failure::Binding | Failure::History => 9,
		};
		Self::new(
			exit_code,
			Outcome::Refused {
				code,
				message: code.message(),
			},
		)
	}

	fn new(exit_code: u8, outcome: Outcome) -> Self {
		Self {
			schema: "exacopy.cli.apfs_recovery_inspection",
			schema_version: "1.0",
			exit_code,
			outcome,
		}
	}

	pub(super) const fn exit_code(&self) -> u8 {
		self.exit_code
	}

	pub(super) fn write(
		&self,
		format: Format,
		stdout: &mut impl Write,
		stderr: &mut impl Write,
	) -> io::Result<()> {
		match format {
			Format::Json => {
				serde_json::to_writer(&mut *stdout, self)?;
				writeln!(stdout)?;
				stdout.flush()
			}
			Format::Human => match &self.outcome {
				Outcome::Refused { message, .. } => {
					writeln!(stderr, "exacopy: {message}")?;
					stderr.flush()
				}
				Outcome::Inspected(observed) => self.write_human(observed, stdout),
			},
		}
	}

	fn write_human(&self, observed: &Observation, output: &mut impl Write) -> io::Result<()> {
		writeln!(output, "Historical state: {}.", observed.historical_status)?;
		writeln!(
			output,
			"Accepted journal: sequence {}, byte {}, digest {}; {} tail.",
			observed.journal_sequence,
			observed.journal_offset,
			observed.journal_head_digest,
			observed.journal_tail,
		)?;
		let receipt = match &observed.receipt {
			Receipt::Missing => "absent",
			Receipt::PresentUncommitted => "present without a commitment",
			Receipt::MatchesHistoricalCommitment { .. } => "matches historical commitment",
		};
		writeln!(output, "Private receipt: {receipt}.")?;
		write_entry(output, "Private stage", observed.stage.as_ref())?;
		write_entry(output, "Public target", observed.target.as_ref())?;
		if self.exit_code != 0 {
			writeln!(output, "Reconciliation required.")?;
		}
		output.flush()
	}
}

fn observation_exit_code(
	status: DarwinReplayStatus,
	tail: DarwinJournalTail,
	receipt: DarwinReceiptArtifact,
) -> u8 {
	use DarwinReceiptArtifact::{MatchesCommitment, Missing};
	use DarwinReplayStatus::{Complete, Conflict, Incomplete};

	match (status, tail, receipt) {
		(Incomplete | Conflict, DarwinJournalTail::Clean, Missing)
		| (Complete, DarwinJournalTail::Clean, MatchesCommitment(_)) => 0,
		_ => 9,
	}
}

fn write_entry(output: &mut impl Write, label: &str, entry: Option<&Entry>) -> io::Result<()> {
	match entry {
		Some(entry) => writeln!(
			output,
			"{label}: observed inode {}, {} bytes.",
			entry.identity.inode, entry.length
		),
		None => writeln!(output, "{label}: absent."),
	}
}

impl From<ManagedObjectIdentity> for Identity {
	fn from(identity: ManagedObjectIdentity) -> Self {
		Self {
			device: identity.device(),
			physical_fsid: identity.physical_fsid(),
			inode: identity.inode().get().to_string(),
			generation: identity.generation().map(std::num::NonZeroU32::get),
			birth_seconds: identity.birth().seconds().to_string(),
			birth_nanoseconds: identity.birth().nanoseconds(),
		}
	}
}

impl From<RecoveryFileObservation> for Entry {
	fn from(entry: RecoveryFileObservation) -> Self {
		Self {
			identity: entry.identity().into(),
			length: entry.length().to_string(),
		}
	}
}

fn hex(bytes: &[u8]) -> String {
	use std::fmt::Write as _;

	let mut out = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		write!(&mut out, "{byte:02x}").expect("writing to a string succeeds");
	}
	out
}

#[cfg(test)]
mod tests;
