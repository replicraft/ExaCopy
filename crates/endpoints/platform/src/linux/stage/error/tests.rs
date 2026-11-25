use std::error::Error;
use std::io;

use exacopy_endpoint::IoError;
use rustix::io::Errno;

use super::{DirectoryBarriersError, PublishError, ReadError, StageError};

#[test]
fn stage_diagnoses_policy_failures_without_a_system_cause() {
	let cases = [
		(StageError::AlreadyExists, "already exists"),
		(StageError::UnsafeDirectory, "directory"),
		(StageError::UnsafeFile, "private staging"),
		(StageError::IdentityChanged, "identity"),
		(StageError::InvalidLength, "length"),
		(StageError::Unflushed, "full file barrier"),
		(StageError::PriorBarrierFailure, "previously failed"),
	];
	for (error, context) in cases {
		assert!(
			error.to_string().contains(context),
			"expected {context:?} in {error}"
		);
		assert!(error.source().is_none());
	}
}

#[test]
fn stage_errors_carry_their_phase_and_original_os_cause() {
	let cases = [
		(
			StageError::on_create(Errno::NOSPC),
			"staging syscall",
			Errno::NOSPC,
		),
		(
			StageError::BarrierFailed(Errno::IO.into()),
			"synchronization",
			Errno::IO,
		),
		(
			StageError::Write(IoError::System {
				offset: 24,
				source: Errno::FBIG.into(),
			}),
			"positioned operation at 24 failed",
			Errno::FBIG,
		),
		(
			StageError::ReadBack(ReadError::System(Errno::ACCESS.into())),
			"reopen",
			Errno::ACCESS,
		),
	];
	for (error, context, errno) in cases {
		assert!(
			error.to_string().contains(context),
			"expected {context:?} in {error}"
		);
		assert_eq!(original_os_code(&error), Some(errno.raw_os_error()));
	}
	assert!(matches!(
		StageError::on_create(Errno::EXIST),
		StageError::AlreadyExists
	));
}

#[test]
fn publication_diagnostics_distinguish_unperformed_uncertain_and_completed_rename() {
	let cases = [
		(PublishError::Conflict, "already exists", None),
		(PublishError::BindingMismatch, "different stage", None),
		(
			PublishError::StageChanged(StageError::System(Errno::NOENT.into())),
			"before publication",
			Some(Errno::NOENT),
		),
		(
			PublishError::Unsupported(Errno::NOSYS.into()),
			"unsupported",
			Some(Errno::NOSYS),
		),
		(
			PublishError::Uncertain(Errno::INTR.into()),
			"uncertain",
			Some(Errno::INTR),
		),
		(
			PublishError::BarriersFailed(DirectoryBarriersError::Stage(Errno::IO.into())),
			"rename succeeded",
			Some(Errno::IO),
		),
		(
			PublishError::BarriersFailed(DirectoryBarriersError::Destination(Errno::NOSPC.into())),
			"destination directory",
			Some(Errno::NOSPC),
		),
	];
	for (error, context, errno) in cases {
		assert!(
			error.to_string().contains(context),
			"expected {context:?} in {error}"
		);
		assert_eq!(original_os_code(&error), errno.map(Errno::raw_os_error));
	}
}

#[test]
fn combined_barrier_diagnosis_reports_both_os_errors() {
	let stage: io::Error = Errno::IO.into();
	let destination: io::Error = Errno::NOSPC.into();
	let stage_message = stage.to_string();
	let destination_message = destination.to_string();
	let combined = DirectoryBarriersError::Both { stage, destination };
	assert!(
		combined.source().is_none(),
		"both causes are preserved in the variant"
	);
	let report = PublishError::BarriersFailed(combined);
	let message = report.to_string();
	assert!(message.contains(&format!("stage directory: {stage_message}")));
	assert!(message.contains(&format!("destination directory: {destination_message}")));
}

fn original_os_code(mut error: &(dyn Error + 'static)) -> Option<i32> {
	while let Some(source) = error.source() {
		error = source;
	}
	error
		.downcast_ref::<io::Error>()
		.and_then(io::Error::raw_os_error)
}
