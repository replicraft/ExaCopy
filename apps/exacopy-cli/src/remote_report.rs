use std::borrow::Cow;
use std::io;
use std::path::PathBuf;

use exacopy_journal::JournalJobId;
use exacopy_journal::frame::FrameWriter;
use exacopy_journal::remote_download::finalization::{
	RemoteDownloadReceipt, RemoteFinalizationBody, RemoteFinalizationRecord,
	RemotePublicationObservation,
};
use exacopy_journal::remote_download::finalization_policy::SftpDataOnlyV1;
use exacopy_transfer::remote_finalization::CommittedRemoteReceipt;
use serde::Serialize;
use uuid::Uuid;

use crate::args::Format;
#[cfg(feature = "experimental-ssh-wireguard")]
use crate::assembly::linux::remote_download::RemoteRouteCloseError;

const PUBLISHED_WITH_OMISSIONS: u8 = 11;

pub(crate) struct RemoteJob {
	pub(crate) id: JournalJobId,
	pub(crate) directory: PathBuf,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RemotePublication {
	NotPublished,
	PublicationUncertain,
	Published,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) enum RemoteFailureKind {
	#[serde(rename = "E_INVALID_REQUEST")]
	InvalidRequest,
	#[serde(rename = "E_CONFLICT")]
	Conflict,
	#[serde(rename = "E_IO")]
	Io,
	#[serde(rename = "E_INTEGRITY")]
	Integrity,
	#[serde(rename = "E_UNSUPPORTED")]
	Unsupported,
	#[serde(rename = "E_AUTHORIZATION")]
	Authorization,
	#[serde(rename = "E_RECOVERY_REQUIRED")]
	RecoveryRequired,
	#[serde(rename = "E_CANCELLED")]
	Cancelled,
}

impl RemoteFailureKind {
	const fn exit_code(self) -> u8 {
		match self {
			Self::InvalidRequest => 2,
			Self::Conflict => 3,
			Self::Io => 4,
			Self::Integrity => 5,
			Self::Unsupported => 6,
			Self::Authorization => 8,
			Self::RecoveryRequired => 9,
			Self::Cancelled => 10,
		}
	}

	const fn message(self) -> &'static str {
		match self {
			Self::InvalidRequest => {
				"remote download arguments or selected configuration were refused"
			}
			Self::Conflict => "the destination name is already occupied",
			Self::Io => "a required remote or local operation failed",
			Self::Integrity => "remote download evidence failed verification",
			Self::Unsupported => "the requested remote download operation is unsupported",
			Self::Authorization => "the selected remote download authority was refused",
			Self::RecoveryRequired => "remote download requires reconciliation",
			Self::Cancelled => "remote download was cancelled",
		}
	}
}

pub(crate) struct RemoteOutcome(Outcome);

#[derive(Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum Outcome {
	PublishedWithOmissions { receipt: PublishedReceipt },
	Failed { error: RemoteFailure },
}

mod receipt;
use receipt::PublishedReceipt;

#[derive(Serialize)]
struct JobReport {
	job_id: String,
	job_directory: String,
	job_directory_bytes_hex: String,
}

impl From<RemoteJob> for JobReport {
	fn from(job: RemoteJob) -> Self {
		Self {
			job_id: Uuid::from_bytes(*job.id.as_bytes()).to_string(),
			job_directory: job.directory.to_string_lossy().into_owned(),
			job_directory_bytes_hex: encode_hex(job.directory.as_os_str().as_encoded_bytes()),
		}
	}
}

#[derive(Serialize)]
struct RemoteFailure {
	code: RemoteFailureKind,
	#[serde(skip)]
	publication: RemotePublication,
	message: Cow<'static, str>,
	#[serde(flatten)]
	job: Option<JobReport>,
}

#[derive(Serialize)]
struct ReportHeader {
	schema: &'static str,
	schema_version: &'static str,
}

const REPORT_HEADER: ReportHeader = ReportHeader {
	schema: "exacopy.cli.remote_download",
	schema_version: "1.0",
};

#[derive(Serialize)]
struct Report<'outcome> {
	#[serde(flatten)]
	header: &'static ReportHeader,
	completed: u8,
	pending: u8,
	publication: RemotePublication,
	verification: Option<&'static str>,
	consistency: Option<&'static str>,
	durability: &'static str,
	durability_qualification: Option<&'static str>,
	preservation: &'static str,
	metadata: Option<&'static str>,
	#[serde(flatten)]
	outcome: &'outcome Outcome,
}

impl RemoteOutcome {
	pub(crate) fn published(receipt: &CommittedRemoteReceipt, job: RemoteJob) -> Self {
		match checked_receipt(receipt, job.id) {
			Some(qualification) => Self(Outcome::PublishedWithOmissions {
				receipt: PublishedReceipt {
					job: job.into(),
					length: receipt.capture.length.to_string(),
					blake3: Some(digest_hex(&receipt.capture.source_digest)),
					receipt_digest: digest_hex(receipt.digest.as_bytes()),
					qualification_digest: digest_hex(&qualification),
					metadata_policy: SftpDataOnlyV1::NAME,
					omissions: SftpDataOnlyV1::omissions()
						.iter()
						.map(|item| item.name())
						.collect(),
					#[cfg(feature = "experimental-verified-prefix-resume")]
					retained_witness: None,
					#[cfg(feature = "experimental-verified-prefix-resume")]
					archive_selection: None,
				},
			}),
			None => Self::recovery_required(RemotePublication::Published, job),
		}
	}

	pub(crate) fn failed(code: RemoteFailureKind, job: Option<RemoteJob>) -> Self {
		Self::failure(code, RemotePublication::NotPublished, job)
	}

	pub(crate) fn recovery_required(publication: RemotePublication, job: RemoteJob) -> Self {
		Self::failure(RemoteFailureKind::RecoveryRequired, publication, Some(job))
	}

	pub(crate) fn resume_capacity(
		limit: crate::assembly::linux::remote_download::ResumeCapacity,
		job: RemoteJob,
	) -> Self {
		Self(Outcome::Failed {
			error: RemoteFailure {
				code: RemoteFailureKind::RecoveryRequired,
				publication: RemotePublication::PublicationUncertain,
				message: format!(
					"{} ({})",
					RemoteFailureKind::RecoveryRequired.message(),
					limit.message()
				)
				.into(),
				job: Some(job.into()),
			},
		})
	}

	#[cfg(feature = "experimental-ssh-wireguard")]
	pub(crate) fn with_unconfirmed_route_retirement(self, _cause: RemoteRouteCloseError) -> Self {
		let mut error = match self.0 {
			Outcome::Failed { error } => error,
			Outcome::PublishedWithOmissions { receipt } => {
				#[cfg(feature = "experimental-verified-prefix-resume")]
				if let Some(witness) = receipt.retained_witness {
					let mut error =
						witness::witness_publication_failure(receipt.job, witness.link_count);
					error.message =
						format!("{} (transport retirement unconfirmed)", error.message).into();
					return Self(Outcome::Failed { error });
				}
				RemoteFailure {
					code: RemoteFailureKind::RecoveryRequired,
					publication: RemotePublication::Published,
					message: RemoteFailureKind::RecoveryRequired.message().into(),
					job: Some(receipt.job),
				}
			}
		};
		error.message = format!("{} (transport retirement unconfirmed)", error.message).into();
		Self(Outcome::Failed { error })
	}

	fn failure(
		code: RemoteFailureKind,
		publication: RemotePublication,
		job: Option<RemoteJob>,
	) -> Self {
		Self(Outcome::Failed {
			error: RemoteFailure {
				code,
				publication,
				message: code.message().into(),
				job: job.map(Into::into),
			},
		})
	}

	pub(crate) fn exit_code(&self) -> u8 {
		match &self.0 {
			Outcome::PublishedWithOmissions { .. } => PUBLISHED_WITH_OMISSIONS,
			Outcome::Failed { error } => error.code.exit_code(),
		}
	}

	pub(crate) fn write(
		&self,
		format: Format,
		stdout: &mut impl io::Write,
		stderr: &mut impl io::Write,
	) -> io::Result<()> {
		match format {
			Format::Json => {
				serde_json::to_writer(&mut *stdout, &self.report())?;
				writeln!(stdout)?;
				stdout.flush()
			}
			Format::Human => match &self.0 {
				Outcome::PublishedWithOmissions { receipt } => {
					#[cfg(feature = "experimental-verified-prefix-resume")]
					if let Some(witness) = &receipt.retained_witness {
						writeln!(
							stdout,
							"Published {} bytes after verifying the retained prefix and reading back the completed stage.",
							receipt.length,
						)?;
						writeln!(
							stdout,
							"Retained a private hard link to the published file. Observed {} links.",
							witness.link_count,
						)?;
					} else {
						write_ordinary_published(stdout, receipt)?;
					}
					#[cfg(not(feature = "experimental-verified-prefix-resume"))]
					write_ordinary_published(stdout, receipt)?;
					writeln!(
						stdout,
						"Observed the file and directory barriers. The destination selection is process-crash qualified.",
					)?;
					writeln!(
						stdout,
						"Metadata omissions: {}",
						receipt.omissions.join(", ")
					)?;
					write_job(stdout, &receipt.job)?;
					writeln!(stdout, "Receipt digest {}.", receipt.receipt_digest)?;
					stdout.flush()
				}
				Outcome::Failed { error } => {
					writeln!(stderr, "exacopy: {}", error.message)?;
					write_publication(stderr, error.publication)?;
					if let Some(job) = &error.job {
						write_job(stderr, job)?;
					}
					stderr.flush()
				}
			},
		}
	}

	pub(crate) fn failed_output(&self, stderr: &mut impl io::Write) -> u8 {
		let _result = writeln!(
			stderr,
			"exacopy: could not write the remote download result"
		);
		match &self.0 {
			Outcome::PublishedWithOmissions { receipt } => {
				let _result = writeln!(
					stderr,
					"The file was published with metadata omissions. Receipt digest {}.",
					receipt.receipt_digest,
				);
				let _result = write_job(stderr, &receipt.job);
				4
			}
			Outcome::Failed { error } => {
				let _result = write_publication(stderr, error.publication);
				if let Some(job) = &error.job {
					let _result = write_job(stderr, job);
				}
				error.code.exit_code()
			}
		}
	}

	fn report(&self) -> Report<'_> {
		let complete = matches!(self.0, Outcome::PublishedWithOmissions { .. });
		let publication = match &self.0 {
			Outcome::PublishedWithOmissions { .. } => RemotePublication::Published,
			Outcome::Failed { error } => error.publication,
		};
		let header = &REPORT_HEADER;
		let verification = complete.then_some("hash_readback");
		#[cfg(feature = "experimental-verified-prefix-resume")]
		let (header, verification) = match &self.0 {
			Outcome::PublishedWithOmissions { receipt } if receipt.retained_witness.is_some() => (
				&witness::REPORT_HEADER,
				Some("verified_prefix_with_witness_readback"),
			),
			_ => (header, verification),
		};
		Report {
			header,
			completed: u8::from(complete),
			pending: u8::from(!complete),
			publication,
			verification,
			consistency: complete.then_some("live_observed"),
			durability: if complete {
				"file_and_directory_barriers_observed"
			} else {
				"unconfirmed"
			},
			durability_qualification: complete.then_some("process_crash_qualification"),
			preservation: "preserve",
			metadata: complete.then_some("explicitly_omitted"),
			outcome: &self.0,
		}
	}
}

fn write_ordinary_published(
	output: &mut impl io::Write,
	receipt: &PublishedReceipt,
) -> io::Result<()> {
	writeln!(
		output,
		"Published {} bytes with BLAKE3 read-back and metadata omissions.",
		receipt.length,
	)
}

fn checked_receipt(receipt: &CommittedRemoteReceipt, job: JournalJobId) -> Option<[u8; 32]> {
	let recorded = RemoteDownloadReceipt::decode(&receipt.canonical_receipt).ok()?;
	if recorded.digest().ok()? != receipt.digest
		|| recorded.scope() != receipt.scope
		|| recorded.binding().context.job != job
	{
		return None;
	}
	let predecessor = recorded.durability();
	let body = RemoteFinalizationBody::ReceiptCommitted {
		digest: receipt.digest,
	};
	let payload = RemoteFinalizationRecord::new(recorded.binding(), predecessor, body)
		.ok()?
		.encode()
		.ok()?;
	let commitment = FrameWriter::new(io::sink(), predecessor)
		.append(body.kind(), &payload)
		.ok()?;
	if commitment != receipt.commitment {
		return None;
	}

	let mut qualification = None;
	for (_, record) in recorded.records() {
		match record.body() {
			RemoteFinalizationBody::VerificationRecorded {
				length,
				source,
				stage,
			} => {
				if length.get() != receipt.capture.length
					|| source.as_bytes() != &receipt.capture.source_digest
					|| stage.as_bytes() != receipt.capture.stage_digest.as_bytes()
				{
					return None;
				}
			}
			RemoteFinalizationBody::PublishObserved(observation) => {
				if observation != RemotePublicationObservation::Published(receipt.target) {
					return None;
				}
			}
			RemoteFinalizationBody::DurabilityRecorded {
				qualification: digest,
				..
			} => {
				qualification = Some(digest);
			}
			_ => {}
		}
	}
	qualification
}

fn digest_hex(bytes: &[u8; 32]) -> String {
	blake3::Hash::from_bytes(*bytes).to_hex().to_string()
}

fn encode_hex(bytes: &[u8]) -> String {
	const HEX: &[u8; 16] = b"0123456789abcdef";
	let mut result = String::with_capacity(bytes.len() * 2);
	for &byte in bytes {
		result.push(char::from(HEX[usize::from(byte >> 4)]));
		result.push(char::from(HEX[usize::from(byte & 0x0f)]));
	}
	result
}

fn write_job(output: &mut impl io::Write, job: &JobReport) -> io::Result<()> {
	writeln!(
		output,
		"Job {} retained in {:?}. Directory bytes in hex: {}.",
		job.job_id, job.job_directory, job.job_directory_bytes_hex,
	)
}

fn write_publication(
	output: &mut impl io::Write,
	publication: RemotePublication,
) -> io::Result<()> {
	match publication {
		RemotePublication::Published => writeln!(
			output,
			"The file was published. Receipt completion requires reconciliation."
		),
		RemotePublication::PublicationUncertain => writeln!(
			output,
			"Publication is uncertain. Preserve the job for reconciliation."
		),
		RemotePublication::NotPublished => Ok(()),
	}
}

#[cfg(feature = "experimental-verified-prefix-resume")]
mod witness;
#[cfg(feature = "experimental-verified-prefix-resume")]
use witness::RetainedWitnessReport;
#[cfg(feature = "experimental-verified-prefix-resume")]
pub(crate) use witness::WitnessedSummary;

#[cfg(test)]
mod tests;
