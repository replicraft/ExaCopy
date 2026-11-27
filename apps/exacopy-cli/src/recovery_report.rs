use std::fmt::Display;
use std::io;

use serde::Serialize;

use crate::args::Format;
use crate::copy_report::ErrorKind;

#[derive(Serialize)]
pub(crate) struct RecoveryOutcome {
	schema: &'static str,
	schema_version: &'static str,
	#[serde(skip)]
	exit_code: u8,
	#[serde(flatten)]
	evidence: Evidence,
}

#[derive(Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum Evidence {
	#[cfg(target_os = "linux")]
	Inspected {
		disposition: &'static str,
		journal_sequence: String,
		journal_offset: String,
		journal_tail: &'static str,
		#[serde(skip_serializing_if = "Option::is_none")]
		issue: Option<&'static str>,
		#[serde(skip_serializing_if = "Option::is_none")]
		artifact_present: Option<bool>,
	},
	Failed {
		code: ErrorKind,
		message: String,
	},
}

impl RecoveryOutcome {
	pub(crate) fn failure(code: ErrorKind, message: impl Display) -> Self {
		Self::new(
			code.exit_code(),
			Evidence::Failed {
				code,
				message: message.to_string(),
			},
		)
	}

	#[cfg(target_os = "linux")]
	pub(crate) fn inspected(inspection: exacopy_transfer::linux::RecoveryInspection) -> Self {
		use exacopy_transfer::linux::{JournalTail, RecoveryDisposition};

		let mut issue = None;
		let mut artifact_present = None;
		let (disposition, exit_code) = match inspection.disposition {
			RecoveryDisposition::RetainedPreparation => ("retained_preparation", 9),
			RecoveryDisposition::PossibleRetry => ("possible_retry", 9),
			RecoveryDisposition::PublishedNeedsBarriers => ("published_needs_barriers", 9),
			RecoveryDisposition::PublishedNeedsReceipt {
				artifact_present: present,
			} => {
				artifact_present = Some(present);
				("published_needs_receipt", 9)
			}
			RecoveryDisposition::Complete => ("complete", 0),
			RecoveryDisposition::Conflict => ("conflict", 3),
			RecoveryDisposition::RequiresReconciliation(reason) => {
				issue = Some(issue_code(reason));
				("requires_reconciliation", 9)
			}
		};
		let journal_tail = match inspection.tail {
			JournalTail::Clean => "clean",
			JournalTail::Torn { .. } => "torn",
		};
		Self::new(
			exit_code,
			Evidence::Inspected {
				disposition,
				journal_sequence: inspection.journal.head.sequence().to_string(),
				journal_offset: inspection.journal.offset.to_string(),
				journal_tail,
				issue,
				artifact_present,
			},
		)
	}

	fn new(exit_code: u8, evidence: Evidence) -> Self {
		Self {
			schema: "exacopy.local_recovery_inspection",
			schema_version: "1.0",
			exit_code,
			evidence,
		}
	}

	pub(crate) const fn exit_code(&self) -> u8 {
		self.exit_code
	}

	pub(crate) fn write(
		&self,
		format: Format,
		stdout: &mut impl io::Write,
		stderr: &mut impl io::Write,
	) -> io::Result<()> {
		match format {
			Format::Human => match &self.evidence {
				#[cfg(target_os = "linux")]
				Evidence::Inspected {
					disposition,
					journal_sequence,
					journal_tail,
					issue,
					..
				} => {
					writeln!(
						stdout,
						"Recovery inspection: {}.",
						disposition.replace('_', " ")
					)?;
					writeln!(
						stdout,
						"Validated journal sequence {journal_sequence} ({journal_tail} tail)."
					)?;
					if let Some(issue) = issue {
						writeln!(stdout, "Evidence issue: {}.", issue.replace('_', " "))?;
					}
					stdout.flush()
				}
				Evidence::Failed { message, .. } => {
					writeln!(stderr, "exacopy: {message}")?;
					stderr.flush()
				}
			},
			Format::Json => {
				serde_json::to_writer(&mut *stdout, self)?;
				writeln!(stdout)?;
				stdout.flush()
			}
		}
	}
}

#[cfg(target_os = "linux")]
pub(crate) fn issue_code(issue: exacopy_transfer::linux::RecoveryIssue) -> &'static str {
	use exacopy_transfer::linux::RecoveryIssue;

	match issue {
		RecoveryIssue::MissingPreparation => "missing_preparation",
		RecoveryIssue::TornJournal => "torn_journal",
		RecoveryIssue::UnrecognizedStage => "unrecognized_stage",
		RecoveryIssue::MissingStageAndTarget => "missing_stage_and_target",
		RecoveryIssue::ContradictoryNames => "contradictory_names",
		RecoveryIssue::StageDirectoryBinding => "stage_directory_binding",
		RecoveryIssue::ContradictoryOutcome => "contradictory_outcome",
		RecoveryIssue::RecordedAttempt => "recorded_attempt",
		RecoveryIssue::StreamMismatch => "stream_mismatch",
		RecoveryIssue::MetadataMismatch => "metadata_mismatch",
		RecoveryIssue::MissingCommittedReceipt => "missing_committed_receipt",
	}
}
