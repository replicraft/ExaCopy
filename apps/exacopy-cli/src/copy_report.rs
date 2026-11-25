use std::fmt::Display;
use std::io;

use serde::Serialize;

use crate::args::Format;

#[derive(Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub(crate) enum CopyOutcome {
	#[cfg(target_os = "linux")]
	Published {
		receipt: CopySuccess,
	},
	Failed {
		error: CopyFailure,
	},
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
pub(crate) struct CopySuccess {
	pub(crate) job_id: String,
	pub(crate) job_directory: String,
	pub(crate) length: String,
	pub(crate) blake3: String,
	pub(crate) receipt_digest: String,
}

#[derive(Serialize)]
pub(crate) struct CopyFailure {
	code: ErrorKind,
	message: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	job_id: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	job_directory: Option<String>,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) enum ErrorKind {
	#[serde(rename = "E_UNSUPPORTED")]
	Unsupported,
	#[cfg(target_os = "linux")]
	#[serde(rename = "E_INVALID_REQUEST")]
	InvalidRequest,
	#[cfg(target_os = "linux")]
	#[serde(rename = "E_CONFLICT")]
	Conflict,
	#[cfg(target_os = "linux")]
	#[serde(rename = "E_IO")]
	Io,
	#[cfg(target_os = "linux")]
	#[serde(rename = "E_INTEGRITY")]
	Integrity,
	#[cfg(target_os = "linux")]
	#[serde(rename = "E_SOURCE_MISMATCH")]
	SourceMismatch,
	#[cfg(target_os = "linux")]
	#[serde(rename = "E_PROFILE_AUTHORIZATION")]
	ProfileAuthorization,
	#[cfg(target_os = "linux")]
	#[serde(rename = "E_RECOVERY_REQUIRED")]
	RecoveryRequired,
}

impl ErrorKind {
	pub(crate) const fn exit_code(self) -> u8 {
		match self {
			Self::Unsupported => 6,
			#[cfg(target_os = "linux")]
			Self::InvalidRequest => 2,
			#[cfg(target_os = "linux")]
			Self::Conflict => 3,
			#[cfg(target_os = "linux")]
			Self::Io => 4,
			#[cfg(target_os = "linux")]
			Self::Integrity | Self::SourceMismatch => 5,
			#[cfg(target_os = "linux")]
			Self::ProfileAuthorization => 8,
			#[cfg(target_os = "linux")]
			Self::RecoveryRequired => 9,
		}
	}
}

impl CopyFailure {
	pub(crate) fn new(code: ErrorKind, error: impl Display) -> Self {
		Self {
			code,
			message: error.to_string(),
			job_id: None,
			job_directory: None,
		}
	}

	#[cfg(target_os = "linux")]
	pub(crate) fn with_job(mut self, id: &str, directory: &str) -> Self {
		self.job_id = Some(id.into());
		self.job_directory = Some(directory.into());
		self
	}
}

#[derive(Serialize)]
struct Report<'outcome> {
	schema: &'static str,
	schema_version: &'static str,
	completed: u8,
	pending: u8,
	publication: &'static str,
	verification: Option<&'static str>,
	consistency: Option<&'static str>,
	durability: &'static str,
	preservation: &'static str,
	redundancy: Option<&'static str>,
	metadata: Option<&'static str>,
	#[serde(flatten)]
	outcome: &'outcome CopyOutcome,
}

impl CopyOutcome {
	pub(crate) fn exit_code(&self) -> u8 {
		match self {
			#[cfg(target_os = "linux")]
			Self::Published { .. } => 0,
			Self::Failed { error } => error.code.exit_code(),
		}
	}

	pub(crate) fn write(
		&self,
		format: Format,
		stdout: &mut impl io::Write,
		stderr: &mut impl io::Write,
	) -> io::Result<()> {
		match format {
			Format::Human => match self {
				#[cfg(target_os = "linux")]
				Self::Published { receipt } => {
					writeln!(
						stdout,
						"Copied {} bytes with BLAKE3 read-back (live_observed, durability unconfirmed).",
						receipt.length
					)?;
					writeln!(
						stdout,
						"Job {} retained in {}/. Receipt digest {}.",
						receipt.job_id, receipt.job_directory, receipt.receipt_digest
					)?;
					stdout.flush()
				}
				Self::Failed { error } => {
					writeln!(stderr, "exacopy: {}", error.message)?;
					if let Some(directory) = &error.job_directory {
						writeln!(stderr, "Job directory for this attempt: {directory}")?;
					}
					stderr.flush()
				}
			},
			Format::Json => {
				serde_json::to_writer(&mut *stdout, &self.report())?;
				writeln!(stdout)?;
				stdout.flush()
			}
		}
	}

	pub(crate) fn failed_output(&self, stderr: &mut impl io::Write, error: &io::Error) -> u8 {
		let _ = writeln!(stderr, "exacopy: could not write the copy result ({error})");
		match self {
			#[cfg(target_os = "linux")]
			Self::Published { receipt } => {
				let _ = writeln!(
					stderr,
					"The copy was published. Its committed receipt is in {}/.",
					receipt.job_directory
				);
				4
			}
			Self::Failed { error } => {
				if let Some(directory) = &error.job_directory {
					let _ = writeln!(stderr, "Job directory for this attempt: {directory}");
				}
				error.code.exit_code()
			}
		}
	}

	fn report(&self) -> Report<'_> {
		let complete = self.exit_code() == 0;
		let publication = match self.exit_code() {
			0 => "published",
			9 => "publication_uncertain",
			_ => "not_published",
		};
		Report {
			schema: "exacopy.cli.copy",
			schema_version: "1.0",
			completed: u8::from(complete),
			pending: u8::from(!complete),
			publication,
			verification: complete.then_some("hash_readback"),
			consistency: complete.then_some("live_observed"),
			durability: "unconfirmed",
			preservation: "preserve",
			redundancy: complete.then_some("independent_writes"),
			metadata: complete.then_some("complete_for_policy"),
			outcome: self,
		}
	}
}
