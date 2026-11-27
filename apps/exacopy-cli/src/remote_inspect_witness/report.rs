use std::io::{self, Write};

use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use serde::Serialize;
use uuid::Uuid;

use crate::args::Format;
use crate::assembly::linux::WitnessedInspectionError;
use crate::copy_report::ErrorKind;

#[derive(Clone, Copy)]
pub(super) enum Failure {
	AliasedInputs,
	ArchiveUnavailable,
	ArchiveInvalid,
	JobName,
	JobMismatch,
	Qualification,
	Destination,
	Buffer,
	Custody,
	History,
	Integrity,
}

impl Failure {
	pub(super) fn from_inspection(cause: WitnessedInspectionError) -> Self {
		use WitnessedInspectionError as Error;

		match cause {
			Error::Job(_) => Self::Custody,
			Error::SubstrateChanged
			| Error::ExecutionMismatch(_)
			| Error::OrdinaryQualification(_)
			| Error::SelectionMismatch => Self::Qualification,
			Error::History { .. } => Self::History,
			Error::PublicData(_) => Self::Custody,
			Error::PublicDigestMismatch | Error::ReceiptMismatch => Self::Integrity,
		}
	}

	const fn public(self) -> (ErrorKind, &'static str) {
		match self {
			Self::AliasedInputs => (
				ErrorKind::InvalidRequest,
				"Inspection inputs must select distinct paths.",
			),
			Self::ArchiveUnavailable => (
				ErrorKind::ProfileAuthorization,
				"The protected selection report was refused.",
			),
			Self::ArchiveInvalid => (
				ErrorKind::InvalidRequest,
				"The selected report is not an accepted witnessed success archive.",
			),
			Self::JobName => (ErrorKind::InvalidRequest, "The job path was refused."),
			Self::JobMismatch => (
				ErrorKind::ProfileAuthorization,
				"The job name does not match the archived selection.",
			),
			Self::Qualification => (
				ErrorKind::ProfileAuthorization,
				"The archived selection or current qualification was refused.",
			),
			Self::Destination => (ErrorKind::Io, "The selected destination could not be held."),
			Self::Buffer => (
				ErrorKind::Io,
				"The bounded inspection buffer is unavailable.",
			),
			Self::Custody => (
				ErrorKind::RecoveryRequired,
				"The protected job or its current files could not be verified.",
			),
			Self::History => (
				ErrorKind::RecoveryRequired,
				"The authenticated journal does not establish the selected committed receipt.",
			),
			Self::Integrity => (
				ErrorKind::Integrity,
				"Current data or receipt evidence does not match the selected commitment.",
			),
		}
	}
}

#[derive(Serialize)]
pub(super) struct Report {
	schema: &'static str,
	schema_version: &'static str,
	authority: &'static str,
	#[serde(flatten)]
	outcome: Outcome,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Outcome {
	Verified {
		job_id: String,
		public_length: String,
		journal: Journal,
		receipt: Receipt,
	},
	Refused {
		error: PublicFailure,
	},
}

#[derive(Serialize)]
struct Journal {
	sequence: String,
	offset: String,
	head_digest: String,
}

#[derive(Serialize)]
struct Receipt {
	digest: String,
	canonical_length: usize,
}

#[derive(Serialize)]
struct PublicFailure {
	code: ErrorKind,
	message: &'static str,
}

impl Report {
	fn new(outcome: Outcome) -> Self {
		Self {
			schema: "exacopy.cli.witnessed_remote_inspection",
			schema_version: "1.0",
			authority: "none",
			outcome,
		}
	}

	pub(super) fn refused(cause: Failure) -> Self {
		let (code, message) = cause.public();
		Self::new(Outcome::Refused {
			error: PublicFailure { code, message },
		})
	}

	pub(super) fn verified(
		job_id: Uuid,
		boundary: RemoteReplayBoundary,
		receipt_digest: [u8; 32],
		receipt_length: usize,
		stream_length: u64,
	) -> Self {
		Self::new(Outcome::Verified {
			job_id: job_id.to_string(),
			public_length: stream_length.to_string(),
			journal: Journal {
				sequence: boundary.head.sequence().to_string(),
				offset: boundary.offset.to_string(),
				head_digest: hex(boundary.head.digest()),
			},
			receipt: Receipt {
				digest: hex(receipt_digest),
				canonical_length: receipt_length,
			},
		})
	}

	pub(super) const fn exit_code(&self) -> u8 {
		match &self.outcome {
			Outcome::Verified { .. } => 0,
			Outcome::Refused { error } => error.code.exit_code(),
		}
	}

	pub(super) fn write(&self, format: Format, stdout: &mut impl Write) -> io::Result<()> {
		match format {
			Format::Json => {
				serde_json::to_writer(&mut *stdout, self)?;
				writeln!(stdout)?;
			}
			Format::Human => match &self.outcome {
				Outcome::Verified {
					job_id,
					public_length,
					journal,
					receipt,
				} => {
					writeln!(
						stdout,
						"Verified the witnessed receipt and {public_length} public bytes for job {job_id}."
					)?;
					writeln!(
						stdout,
						"Journal sequence {} at byte {}.",
						journal.sequence, journal.offset
					)?;
					writeln!(stdout, "Receipt digest {}.", receipt.digest)?;
				}
				Outcome::Refused { error } => {
					writeln!(stdout, "Witness inspection refused. {}", error.message)?
				}
			},
		}
		stdout.flush()
	}
}

fn hex(digest: [u8; 32]) -> String {
	blake3::Hash::from_bytes(digest).to_hex().to_string()
}

#[cfg(test)]
mod tests {
	use exacopy_journal::frame::ChainHead;
	use serde_json::json;

	use super::*;

	#[test]
	fn witness_inspection_projects_verified_commitment_and_redacts_refusals() {
		let job_id = Uuid::from_bytes([1; 16]);
		let verified = Report::verified(
			job_id,
			RemoteReplayBoundary {
				head: ChainHead::after(22, [2; 32]).unwrap(),
				offset: 8192,
			},
			[3; 32],
			1200,
			64,
		);
		assert_eq!(verified.exit_code(), 0);
		assert_eq!(
			serde_json::to_value(verified).unwrap(),
			json!({
				"schema": "exacopy.cli.witnessed_remote_inspection",
				"schema_version": "1.0",
				"authority": "none",
				"status": "verified",
				"job_id": job_id.to_string(),
				"public_length": "64",
				"journal": { "sequence": "22", "offset": "8192", "head_digest": "02".repeat(32) },
				"receipt": { "digest": "03".repeat(32), "canonical_length": 1200 },
			})
		);
		let refused = Report::refused(Failure::ArchiveUnavailable);
		assert_eq!(refused.exit_code(), 8);
		assert_eq!(
			serde_json::to_value(refused).unwrap(),
			json!({
				"schema": "exacopy.cli.witnessed_remote_inspection",
				"schema_version": "1.0",
				"authority": "none",
				"status": "refused",
				"error": {
					"code": "E_PROFILE_AUTHORIZATION",
					"message": "The protected selection report was refused.",
				},
			})
		);
	}
}
