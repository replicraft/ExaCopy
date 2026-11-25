use std::io;

use crate::macos::ManagedReadError;

use super::attempt::{RenameOutcome, finish_attempt};
use super::{DirectoryBarrierFailures, PublishError, PublishRejection};

#[test]
fn a_multiple_failure_report_keeps_each_directory_error_and_known_rename() {
	let errors = DirectoryBarrierFailures::from_results(
		Err(io::Error::from_raw_os_error(libc::EIO)),
		Err(io::Error::from_raw_os_error(libc::ENOSPC)),
	);
	let result = finish_attempt(
		Some(Ok(RenameOutcome::Renamed {
			barriers: errors,
			observation: None,
		})),
		Err(ManagedReadError::RestoreMaterializationPolicy(
			io::ErrorKind::PermissionDenied.into(),
		)),
	);
	let Err(PublishError::Renamed {
		barriers: Some(barriers),
		observation: None,
		policy_error: Some(_),
	}) = result
	else {
		panic!("expected both barrier failures and policy failure after known rename: {result:?}");
	};
	assert_eq!(
		barriers.stage().and_then(io::Error::raw_os_error),
		Some(libc::EIO)
	);
	assert_eq!(
		barriers.destination().and_then(io::Error::raw_os_error),
		Some(libc::ENOSPC)
	);
}

#[test]
fn policy_failure_cannot_hide_rejection_conflict_or_uncertainty() {
	let restore_error = || {
		Err(ManagedReadError::RestoreMaterializationPolicy(
			io::ErrorKind::PermissionDenied.into(),
		))
	};

	assert!(matches!(
		finish_attempt(
			None,
			Err(ManagedReadError::MaterializationPolicy(
				io::ErrorKind::PermissionDenied.into()
			))
		),
		Err(PublishError::Rejected {
			reason: PublishRejection::Policy,
			policy_error: Some(_)
		})
	));
	assert!(matches!(
		finish_attempt(Some(Ok(RenameOutcome::Conflict)), restore_error()),
		Err(PublishError::Conflict {
			policy_error: Some(_)
		})
	));
	assert!(matches!(
		finish_attempt(Some(Ok(RenameOutcome::Uncertain(io::Error::from_raw_os_error(libc::EIO)))), restore_error()),
		Err(PublishError::Uncertain { error, policy_error: Some(_) }) if error.raw_os_error() == Some(libc::EIO)
	));
}

mod adapter;
