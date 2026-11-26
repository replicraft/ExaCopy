use apfs_mounted::dataless::PolicyError;
use apfs_mounted::writer::{BarrierError, BarrierKind};

use super::*;

fn restore(outcome: Result<LifecycleEffect, WriterError>) -> WriterError {
	WriterError::Restore {
		error: PolicyError::Io(io::Error::from_raw_os_error(libc::EIO)),
		outcome: outcome.map_err(Box::new),
	}
}

#[test]
fn creation_outcomes_preserve_effect_boundaries() {
	let cases = [
		(WriterError::Occupied, None),
		(
			WriterError::Configure {
				error: PolicyError::UnknownPolicy(17),
				restoration: Some(PolicyError::UnknownPolicy(19)),
			},
			None,
		),
		(
			WriterError::CreationRefused(Box::new(JobError::IdentityChanged)),
			None,
		),
		(restore(Err(WriterError::Occupied)), None),
		(
			restore(Err(WriterError::CreationRefused(Box::new(
				JobError::IdentityChanged,
			)))),
			None,
		),
		(
			WriterError::CreateUncertain(io::ErrorKind::Other.into()),
			Some(JobStep::Create),
		),
		(
			WriterError::CreatedButUnverified(Box::new(WriterError::NotPrivate)),
			Some(JobStep::Bind),
		),
		(restore(Ok(LifecycleEffect::Created)), Some(JobStep::Bind)),
		(
			restore(Err(WriterError::CreatedButUnverified(Box::new(
				WriterError::Changed,
			)))),
			Some(JobStep::Bind),
		),
	];
	for (error, expected) in cases {
		assert_eq!(
			artifact_step(ArtifactPhase::Create, &error),
			expected,
			"{error:?}"
		);
	}
}

#[test]
fn flush_and_close_preserve_the_native_effect_report() {
	let cases = [
		(WriterError::Changed, JobStep::Write),
		(
			WriterError::Barrier(BarrierError {
				kind: BarrierKind::FullFile,
				error: io::Error::from_raw_os_error(libc::EIO),
			}),
			JobStep::FileBarrier,
		),
		(
			WriterError::BarrierPassedButUnverified(Box::new(WriterError::Changed)),
			JobStep::FileBarrier,
		),
		(
			WriterError::Close(io::ErrorKind::Other.into()),
			JobStep::Close,
		),
		(
			WriterError::ClosedButUnverified(Box::new(WriterError::Changed)),
			JobStep::Verify,
		),
		(restore(Ok(LifecycleEffect::Observed)), JobStep::Write),
		(restore(Ok(LifecycleEffect::Closed)), JobStep::Verify),
		(
			restore(Err(WriterError::Close(io::ErrorKind::Other.into()))),
			JobStep::Close,
		),
	];
	for (error, step) in cases {
		assert_eq!(
			artifact_step(ArtifactPhase::FlushAndClose, &error),
			Some(step),
			"{error:?}"
		);
	}
}

#[test]
fn typed_caller_denial_round_trips_and_restore_retains_both_errors() {
	let denied = job_failure(WriterError::CreationRefused(Box::new(
		JobError::IdentityChanged,
	)));
	assert!(matches!(denied, JobError::IdentityChanged));
	let denied = job_failure(WriterError::CreatedButUnverified(Box::new(
		WriterError::MetadataRefused(Box::new(JobError::InvalidLength)),
	)));
	assert!(matches!(denied, JobError::InvalidLength));

	let restored = job_failure(restore(Err(WriterError::Close(
		io::Error::from_raw_os_error(libc::ENOSPC),
	))));
	assert!(matches!(
		restored,
		JobError::Managed(StageError::Mounted(WriterError::Restore {
			error: PolicyError::Io(ref error),
			outcome: Err(ref cause),
		})) if error.raw_os_error() == Some(libc::EIO)
			&& matches!(**cause, WriterError::Close(ref error)
				if error.raw_os_error() == Some(libc::ENOSPC))
	));
}
