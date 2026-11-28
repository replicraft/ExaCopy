use std::future::{Future as _, pending};
use std::io;
use std::pin::pin;
use std::task::{Context, Waker};

use ed25519_dalek::SigningKey;
use exacopy_journal::windows_bootstrap::{
	WindowsBootstrapOwner, WindowsBootstrapRoles, WindowsBootstrapSelection, inspect, sign,
};
use exacopy_journal::{JournalJobId, OwnerProfileId, OwnerToken};

use super::*;

#[test]
fn refused_append_reports_possible_changes_without_a_confirmed_boundary() {
	let progress = Progress::default();
	let refusal = progress.failure(WindowsCaptureError::Custody(
		exacopy_platform::ProtectedSnapshotError::Changed,
	));
	assert_eq!(refusal.progress(), &WindowsCaptureProgress::default());

	progress.update(|state| state.local_changes_may_exist = true);
	let refusal = progress.failure(WindowsCaptureError::BootstrapAppend(
		io::ErrorKind::PermissionDenied.into(),
	));
	assert!(refusal.progress().local_changes_may_exist);
	assert!(refusal.progress().bootstrap.is_none());
	assert!(refusal.progress().checkpoint.is_none());
	assert!(refusal.progress().measured.is_none());
	assert!(matches!(
		refusal.cause(),
		WindowsCaptureError::BootstrapAppend(cause)
			if cause.kind() == io::ErrorKind::PermissionDenied
	));
	assert!(refusal.source().unwrap().is::<WindowsCaptureError>());
}

#[test]
fn dropped_capture_future_preserves_the_previously_confirmed_boundary() {
	// Use real signed and decoded V1 values. The future models suspension after
	// the independent native confirmation, without simulating a native barrier.
	let boundary = signed_bootstrap_boundary();
	let progress = Progress::default();
	progress.update(|state| state.local_changes_may_exist = true);
	{
		let mut capture = pin!(async {
			progress.update(|state| state.bootstrap = Some(boundary));
			pending::<()>().await;
			unreachable!("capture was cancelled before closeout");
		});
		let mut context = Context::from_waker(Waker::noop());
		assert!(capture.as_mut().poll(&mut context).is_pending());
	}
	let failure = progress.failure(WindowsCaptureError::Deadline);
	assert_eq!(failure.progress().bootstrap, Some(boundary));
	assert!(failure.progress().local_changes_may_exist);
	assert!(!failure.progress().native_closeout_confirmed);
	assert!(!failure.progress().route_shutdown_confirmed);
	assert!(matches!(failure.cause(), WindowsCaptureError::Deadline));
}

fn signed_bootstrap_boundary() -> WindowsBootstrapPrefix {
	let key = SigningKey::from_bytes(&[0x27; 32]);
	let identity = |tag| {
		WindowsBootstrapFileIdentity::new(*b"01a34567-89ab-cdef-9abc-012de3456789", 0x17, [tag; 16])
			.unwrap()
	};
	let owner = WindowsBootstrapOwner {
		profile: OwnerProfileId::from_bytes([0x62; 16]).unwrap(),
		job: JournalJobId::from_bytes([
			0x01, 0x8d, 0x45, 0xbe, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1,
		])
		.unwrap(),
		token: OwnerToken::from_bytes([0x61; 16]).unwrap(),
		roles: WindowsBootstrapRoles::new(
			identity(1),
			identity(2),
			identity(3),
			identity(4),
			identity(5),
		)
		.unwrap(),
	};
	let bytes = sign(&owner, &key).unwrap();
	inspect(
		&bytes.owner,
		bytes.first_segment.as_slice(),
		&WindowsBootstrapSelection {
			profile: owner.profile,
			job: owner.job,
			key: &key.verifying_key(),
			root: identity(1),
		},
		owner.roles,
	)
	.unwrap()
	.boundary()
}
