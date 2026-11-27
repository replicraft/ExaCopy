use exacopy_journal::remote_download::{
	finalization_policy::SftpOmission, replay::RemoteReplayBoundary,
};
use serde::Serialize;

use crate::assembly::linux::ArchivedWitnessedSelection;

use super::{
	JobReport, Outcome, PublishedReceipt, RemoteFailure, RemoteFailureKind, RemoteJob,
	RemoteOutcome, RemotePublication, SftpDataOnlyV1, digest_hex,
};

pub(super) const REPORT_HEADER: super::ReportHeader = super::ReportHeader {
	schema: "exacopy.cli.witnessed_remote_download",
	schema_version: "1.1",
};

#[derive(Serialize)]
pub(super) struct RetainedWitnessReport {
	pub(super) link_count: u64,
	committed_sequence: String,
	committed_head_digest: String,
	canonical_receipt_length: usize,
}

pub(crate) struct WitnessedSummary {
	pub(crate) archive_selection: ArchivedWitnessedSelection,
	pub(crate) committed: RemoteReplayBoundary,
	pub(crate) length: u64,
	pub(crate) receipt_digest: [u8; 32],
	pub(crate) canonical_receipt_length: usize,
	pub(crate) qualification: [u8; 32],
	pub(crate) witness_links: u64,
	pub(crate) metadata_omissions: &'static [SftpOmission],
}

impl RemoteOutcome {
	pub(crate) fn published_with_witness(job: RemoteJob, summary: WitnessedSummary) -> Self {
		if summary.archive_selection.job != job.id
			|| summary.archive_selection.committed != summary.committed
			|| summary.archive_selection.receipt_digest != summary.receipt_digest
			|| summary.archive_selection.op2_digest != summary.qualification
		{
			return Self::recovery_required(RemotePublication::Published, job);
		}
		Self(Outcome::PublishedWithOmissions {
			receipt: PublishedReceipt {
				job: job.into(),
				length: summary.length.to_string(),
				blake3: None,
				archive_selection: Some(Box::new(summary.archive_selection)),
				receipt_digest: digest_hex(&summary.receipt_digest),
				qualification_digest: digest_hex(&summary.qualification),
				metadata_policy: SftpDataOnlyV1::NAME,
				omissions: summary
					.metadata_omissions
					.iter()
					.map(|item| item.name())
					.collect(),
				retained_witness: Some(RetainedWitnessReport {
					link_count: summary.witness_links,
					committed_sequence: summary.committed.head.sequence().to_string(),
					committed_head_digest: digest_hex(&summary.committed.head.digest()),
					canonical_receipt_length: summary.canonical_receipt_length,
				}),
			},
		})
	}

	pub(crate) fn witness_reconciliation(job: RemoteJob, links: u64) -> Self {
		Self(Outcome::Failed {
			error: witness_publication_failure(job.into(), links),
		})
	}

	pub(crate) fn witness_conflict_reconciliation(job: RemoteJob) -> Self {
		Self(Outcome::Failed {
			error: RemoteFailure {
				code: RemoteFailureKind::RecoveryRequired,
				publication: RemotePublication::NotPublished,
				message: "remote download requires reconciliation (incumbent observed; conflict record unconfirmed)".into(),
				job: Some(job.into()),
			},
		})
	}

	pub(crate) fn witness_capture_reconciliation(job: RemoteJob, sequence: u64, end: u64) -> Self {
		Self(Outcome::Failed {
			error: RemoteFailure {
				code: RemoteFailureKind::RecoveryRequired,
				publication: RemotePublication::PublicationUncertain,
				message: format!(
					"{} (last confirmed capture record {sequence}, journal byte {end})",
					RemoteFailureKind::RecoveryRequired.message()
				)
				.into(),
				job: Some(job.into()),
			},
		})
	}
}

pub(super) fn witness_publication_failure(job: JobReport, links: u64) -> RemoteFailure {
	RemoteFailure {
		code: RemoteFailureKind::RecoveryRequired,
		publication: RemotePublication::Published,
		message: format!(
			"{} (private witness retained, {links} links observed)",
			RemoteFailureKind::RecoveryRequired.message()
		)
		.into(),
		job: Some(job),
	}
}
