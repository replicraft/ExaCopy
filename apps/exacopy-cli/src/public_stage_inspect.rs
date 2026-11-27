use std::io::{self, Write};
use std::path::Path;

use ed25519_dalek::VerifyingKey;
use exacopy_content::MAX_SCRATCH_BYTES;
use exacopy_platform::linux::StageError;
use exacopy_transfer::linux::{
	AuthenticatedPublicStage, JournalBoundary, JournalTail, PublicStageHistory,
	PublicStageInspection, PublicStageObservation, RecoveryProfile,
};
use serde::Serialize;

use crate::args::{Format, PublicStageInspectCommand};
use crate::assembly::linux::{RecoveryInspectError, public_stage};
use crate::copy_report::ErrorKind;
use crate::linux_path::{open_destination, split};
use crate::profile::profile_id_for_key;
use crate::recovery_report::issue_code;

#[derive(Serialize)]
struct Report {
	schema: &'static str,
	schema_version: &'static str,
	authority: &'static str,
	status: &'static str,
	#[serde(skip_serializing_if = "Option::is_none")]
	reason: Option<&'static str>,
	#[serde(skip_serializing_if = "Option::is_none")]
	historical_binding: Option<HistoricalBinding>,
	#[serde(skip_serializing_if = "Option::is_none")]
	journal: Option<JournalEvidence>,
	#[serde(skip)]
	exit: u8,
}

#[derive(Serialize)]
struct HistoricalBinding {
	owner_digest: String,
	private_plan_digest: String,
	public_plan_digest: String,
}

#[derive(Serialize)]
struct JournalEvidence {
	sequence: String,
	accepted_offset: String,
	tail: &'static str,
}

impl Report {
	fn new(status: &'static str, exit: u8) -> Self {
		Self {
			schema: "exacopy.public_stage_inspection",
			schema_version: "1.0",
			authority: "none",
			status,
			reason: None,
			historical_binding: None,
			journal: None,
			exit,
		}
	}

	fn failure(reason: &'static str, kind: ErrorKind) -> Self {
		Self {
			reason: Some(reason),
			..Self::new("refused", kind.exit_code())
		}
	}
}

pub(crate) fn run(
	command: &PublicStageInspectCommand,
	stdout: &mut impl Write,
	stderr: &mut impl Write,
) -> u8 {
	let report = inspect(command);
	if write_report(&report, command.format, stdout).is_err() {
		let _ = writeln!(
			stderr,
			"exacopy: could not write the public-stage inspection"
		);
		return ErrorKind::Io.exit_code();
	}
	report.exit
}

fn write_report(report: &Report, format: Format, stdout: &mut impl Write) -> io::Result<()> {
	match format {
		Format::Human => {
			write!(
				stdout,
				"Public-stage inspection: {}",
				report.status.replace('_', " ")
			)?;
			if let Some(reason) = report.reason {
				write!(stdout, " ({})", reason.replace('_', " "))?;
			}
			writeln!(stdout, ".")?;
		}
		Format::Json => {
			serde_json::to_writer(&mut *stdout, report)?;
			writeln!(stdout)?;
		}
	}
	stdout.flush()
}

fn inspect(command: &PublicStageInspectCommand) -> Report {
	let Some(key) = verified_key(command.owner_key) else {
		return Report::failure("owner_key_refused", ErrorKind::ProfileAuthorization);
	};
	let Ok(id) = profile_id_for_key(&key) else {
		return Report::failure("owner_key_refused", ErrorKind::ProfileAuthorization);
	};
	let Ok((parent, job)) = split(&command.job) else {
		return Report::failure("invalid_job_name", ErrorKind::InvalidRequest);
	};
	let Ok(destination) = open_destination(Path::new(parent)) else {
		return Report::failure("destination_unavailable", ErrorKind::Io);
	};
	let mut scratch = Vec::new();
	if scratch.try_reserve_exact(MAX_SCRATCH_BYTES).is_err() {
		return Report::failure("inspection_buffer_unavailable", ErrorKind::Io);
	}
	scratch.resize(MAX_SCRATCH_BYTES, 0);
	let profile = RecoveryProfile {
		id,
		verifying_key: &key,
	};
	match public_stage::inspect(&destination, job, profile, &mut scratch) {
		Ok(observation) => project(observation),
		Err(error) => refusal(&error),
	}
}

fn verified_key(raw: [u8; 32]) -> Option<VerifyingKey> {
	let key = VerifyingKey::from_bytes(&raw).ok()?;
	(raw != [0; 32] && !key.is_weak() && key.to_edwards().compress().to_bytes() == raw)
		.then_some(key)
}

fn refusal(error: &RecoveryInspectError) -> Report {
	use ErrorKind::{Integrity, InvalidRequest, Io, ProfileAuthorization, RecoveryRequired};

	match error {
		RecoveryInspectError::Owner(_) | RecoveryInspectError::OwnerBinding => {
			Report::failure("owner_binding_refused", ProfileAuthorization)
		}
		RecoveryInspectError::Platform {
			source: StageError::JobBusy,
			..
		} => Report::failure("job_busy", RecoveryRequired),
		RecoveryInspectError::Platform {
			source: StageError::IdentityChanged,
			..
		}
		| RecoveryInspectError::RecordChanged(_) => Report::failure("evidence_changed", RecoveryRequired),
		RecoveryInspectError::Platform { .. }
		| RecoveryInspectError::Read { .. }
		| RecoveryInspectError::ReadBack(_) => Report::failure("observation_unavailable", Io),
		RecoveryInspectError::Input(_) => {
			Report::failure("invalid_inspection_input", InvalidRequest)
		}
		RecoveryInspectError::Journal(_) => Report::failure("journal_refused", Integrity),
		_ => Report::failure("evidence_refused", Integrity),
	}
}

fn project(observation: PublicStageInspection) -> Report {
	let PublicStageInspection::Authenticated { evidence, history } = observation else {
		return Report::new(
			"owner_missing_observed",
			ErrorKind::RecoveryRequired.exit_code(),
		);
	};
	let pending = ErrorKind::RecoveryRequired.exit_code();
	let mut report = match history {
		PublicStageHistory::PlanMissing => Report::new("plan_missing_observed", pending),
		PublicStageHistory::JournalMissing => Report::new("journal_missing_observed", pending),
		PublicStageHistory::Journal {
			boundary,
			tail,
			observation,
		} => project_journal(boundary, tail, observation),
	};
	report.historical_binding = Some(historical_binding(&evidence));
	report
}

fn historical_binding(evidence: &AuthenticatedPublicStage) -> HistoricalBinding {
	let hex = |value: &[u8; 32]| blake3::Hash::from_bytes(*value).to_hex().to_string();
	HistoricalBinding {
		owner_digest: hex(evidence.owner_digest.as_bytes()),
		private_plan_digest: hex(evidence.private_plan.as_bytes()),
		public_plan_digest: hex(evidence.binding.public_plan.as_bytes()),
	}
}

fn project_journal(
	boundary: JournalBoundary,
	tail: JournalTail,
	observation: PublicStageObservation,
) -> Report {
	use PublicStageObservation as Stage;

	let pending = ErrorKind::RecoveryRequired.exit_code();
	let clean = matches!(tail, JournalTail::Clean);
	let mut report = match observation {
		Stage::EmptyJournal => Report::new("empty_journal", pending),
		Stage::RetainedPreparation => Report::new("retained_preparation", pending),
		Stage::RetainedPartialStage => Report::new("retained_partial_stage", pending),
		Stage::RetainedVerifiedStage if clean => Report::new("retained_verified_stage", 0),
		Stage::RetainedVerifiedStage => {
			let mut report = Report::new("requires_reconciliation", pending);
			report.reason = Some("torn_journal");
			report
		}
		Stage::UnexpectedTarget => {
			Report::new("unexpected_target", ErrorKind::Conflict.exit_code())
		}
		Stage::UnexpectedReceipt => Report::new("unexpected_receipt", pending),
		Stage::RequiresReconciliation(reason) => {
			let mut report = Report::new("requires_reconciliation", pending);
			report.reason = Some(issue_code(reason));
			report
		}
	};
	let tail = if clean { "clean" } else { "torn" };
	report.journal = Some(JournalEvidence {
		sequence: boundary.head.sequence().to_string(),
		accepted_offset: boundary.offset.to_string(),
		tail,
	});
	report
}

#[cfg(test)]
mod tests;
