//! Verification-only foreground composition for a committed witnessed receipt.

use std::io::Write;
use std::path::Path;

use exacopy_content::MAX_SCRATCH_BYTES;
use exacopy_journal::remote_download::qualification::continuation::{
	RemoteContinuationCoverageProfile, RemoteContinuationOperationProfile,
	RemoteContinuationQualificationScope, RemoteContinuationQualificationTrust,
	verify_remote_witness_qualification,
};
use exacopy_journal::remote_download::qualification::{
	MAX_REMOTE_QUALIFICATION_BYTES, RemoteQualificationTrust,
};
use exacopy_journal::remote_download::witness::records::RemoteWitnessedOutcome;
use uuid::Uuid;

use crate::args::RemoteInspectWitnessCommand;
use crate::assembly::linux::WitnessedInspectionRequest;
use crate::copy_report::ErrorKind;
use crate::linux_path::{open_destination, split};
use crate::remote::qualification::{SelectedTrust, read_bounded};
use crate::witness_archive::{self, ArchiveError};

mod report;

use report::{Failure, Report};

pub(crate) fn run(
	command: &RemoteInspectWitnessCommand,
	stdout: &mut impl Write,
	stderr: &mut impl Write,
) -> u8 {
	let report = match inspect(command) {
		Ok(report) => report,
		Err(failure) => Report::refused(failure),
	};
	if report.write(command.format, stdout).is_err() {
		let _ = writeln!(
			stderr,
			"exacopy: could not write the witnessed inspection report"
		);
		return ErrorKind::Io.exit_code();
	}
	report.exit_code()
}

fn inspect(command: &RemoteInspectWitnessCommand) -> Result<Report, Failure> {
	let paths = [
		command.selection_report.as_path(),
		command.destination_qualification.as_path(),
		command.qualification_trust.as_path(),
		command.continuation_qualification.as_path(),
		command.continuation_trust.as_path(),
	];
	if paths
		.iter()
		.enumerate()
		.any(|(index, path)| paths[..index].contains(path))
	{
		return Err(Failure::AliasedInputs);
	}
	let archive =
		witness_archive::load(&command.selection_report).map_err(|cause| match cause {
			ArchiveError::Snapshot => Failure::ArchiveUnavailable,
			ArchiveError::Format => Failure::ArchiveInvalid,
		})?;
	let selection = &archive.selection;
	let (parent, name) = split(&command.job).map_err(|_| Failure::JobName)?;
	let job_id = Uuid::from_bytes(*selection.job.as_bytes());
	if name.as_bytes() != format!(".exacopy-{job_id}").as_bytes() {
		return Err(Failure::JobMismatch);
	}
	let op1 =
		SelectedTrust::load_v1(&command.qualification_trust).map_err(|_| Failure::Qualification)?;
	let op2 = SelectedTrust::load_witness(&command.continuation_trust)
		.map_err(|_| Failure::Qualification)?;
	if op1.scope.route != selection.route || op2.scope.route != selection.route {
		return Err(Failure::Qualification);
	}
	let op1_record =
		read_bounded::<MAX_REMOTE_QUALIFICATION_BYTES>(&command.destination_qualification)
			.map_err(|_| Failure::Qualification)?;
	let op2_record =
		read_bounded::<MAX_REMOTE_QUALIFICATION_BYTES>(&command.continuation_qualification)
			.map_err(|_| Failure::Qualification)?;
	let qualification = verify_remote_witness_qualification(
		&op2_record,
		&RemoteContinuationQualificationTrust {
			attestor: op2.attestor,
			attestor_key: &op2.key,
			owner_key: &selection.owner_key,
			scope: RemoteContinuationQualificationScope {
				common: op2.scope,
				operation: RemoteContinuationOperationProfile::VerifiedRetainedAppendWithWitnessV1,
				coverage:
					RemoteContinuationCoverageProfile::RetainedAppendWithWitnessProcessCrashV1,
			},
		},
	)
	.map_err(|_| Failure::Qualification)?;
	let root = open_destination(Path::new(parent)).map_err(|_| Failure::Destination)?;
	let mut scratch = Vec::new();
	scratch
		.try_reserve_exact(MAX_SCRATCH_BYTES)
		.map_err(|_| Failure::Buffer)?;
	scratch.resize(MAX_SCRATCH_BYTES, 0);
	let inspection = WitnessedInspectionRequest {
		root: &root,
		archived: selection,
		op1_record: &op1_record,
		op1_trust: &RemoteQualificationTrust {
			attestor: op1.attestor,
			attestor_key: &op1.key,
			owner_key: &selection.owner_key,
			scope: op1.scope,
		},
		qualification: &qualification,
	}
	.inspect(&mut scratch)
	.map_err(Failure::from_inspection)?;
	if !matches!(inspection.recorded, RemoteWitnessedOutcome::Submitted(_))
		|| inspection.committed != selection.committed
		|| inspection.receipt_digest != selection.receipt_digest
		|| inspection.canonical_receipt.len() != archive.receipt_length
		|| inspection.stream_length != archive.stream_length
	{
		return Err(Failure::Integrity);
	}
	Ok(Report::verified(
		job_id,
		inspection.committed,
		inspection.receipt_digest,
		inspection.canonical_receipt.len(),
		inspection.stream_length,
	))
}
