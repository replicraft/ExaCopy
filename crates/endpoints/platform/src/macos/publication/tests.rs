use std::io;
use std::os::fd::AsFd as _;

use crate::macos::ManagedReadError;
use crate::scratch::Scratch;

use super::super::{ManagedObjectIdentity, PhysicalFsid};
use super::attempt::{RenameOutcome, finish_attempt};
use super::evidence::PublicationObservation;
use super::{DirectoryBarrierFailures, PublishError, PublishRejection};

fn observed_identity(scratch: &Scratch) -> ManagedObjectIdentity {
	let directory = scratch.open();
	let stat = rustix::fs::fstat(&directory).expect("inspect fixture descriptor");
	let fsid = PhysicalFsid::held(directory.as_fd())
		.expect("inspect fixture filesystem")
		.expect("receive valid physical FSID");
	ManagedObjectIdentity::from_stat(&stat, fsid).expect("represent fixture identity")
}

#[test]
fn complete_publication_returns_only_the_supplied_identities() {
	let target = Scratch::new();
	let stage_directory = Scratch::new();
	let destination_directory = Scratch::new();
	let target = observed_identity(&target);
	let stage_directory = observed_identity(&stage_directory);
	let destination_directory = observed_identity(&destination_directory);
	let renamed = || {
		Some(Ok(RenameOutcome::Renamed {
			barriers: None,
			observation: Ok(PublicationObservation {
				target,
				stage_directory,
				destination_directory,
			}),
		}))
	};
	let published = finish_attempt(renamed(), Ok(())).expect("all publication checks passed");
	assert_eq!(published.target_identity(), target);
	assert_eq!(published.synced_stage_directory(), stage_directory);
	assert_eq!(
		published.synced_destination_directory(),
		destination_directory
	);
	assert!(matches!(
		finish_attempt(
			renamed(),
			Err(ManagedReadError::RestoreMaterializationPolicy(
				io::ErrorKind::PermissionDenied.into(),
			))
		),
		Err(PublishError::Renamed {
			barriers: None,
			observation: None,
			observed_target: Some(observed_target),
			policy_error: Some(_),
		}) if observed_target == target
	));
}

#[test]
fn a_multiple_failure_report_keeps_each_directory_error_and_known_rename() {
	let scratch = Scratch::new();
	let identity = observed_identity(&scratch);
	let errors = DirectoryBarrierFailures::from_results(
		Err(io::Error::from_raw_os_error(libc::EIO)),
		Err(io::Error::from_raw_os_error(libc::ENOSPC)),
	);
	let result = finish_attempt(
		Some(Ok(RenameOutcome::Renamed {
			barriers: errors,
			observation: Ok(PublicationObservation {
				target: identity,
				stage_directory: identity,
				destination_directory: identity,
			}),
		})),
		Err(ManagedReadError::RestoreMaterializationPolicy(
			io::ErrorKind::PermissionDenied.into(),
		)),
	);
	let Err(PublishError::Renamed {
		barriers: Some(barriers),
		observation: None,
		observed_target: Some(observed_target),
		policy_error: Some(_),
	}) = result
	else {
		panic!("expected both barrier failures and policy failure after known rename: {result:?}");
	};
	assert_eq!(observed_target, identity);
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
