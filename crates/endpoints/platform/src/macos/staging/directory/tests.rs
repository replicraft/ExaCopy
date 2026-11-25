use std::fs::File;

use rustix::fs::{FlockOperation, flock};
use rustix::io::Errno;

use super::super::tests::{Fixture, name, open_staging};
use super::StageError;

#[test]
fn dropping_either_owned_lease_unlocks_its_open_description_despite_a_duplicate() {
	let fixture = Fixture::new();
	let root = fixture.bind();
	let root_alias = root
		.lease
		.file
		.try_clone()
		.expect("duplicate destination lease descriptor");
	let private = fixture.path("private-stage");
	let directory = open_staging(&root);
	let child_alias = directory
		.lease
		.file
		.try_clone()
		.expect("duplicate staging lease descriptor");
	let contender = File::open(private).expect("open an independent staging descriptor");

	assert_eq!(
		flock(&contender, FlockOperation::NonBlockingLockExclusive),
		Err(Errno::AGAIN)
	);
	drop(directory);
	flock(&contender, FlockOperation::NonBlockingLockExclusive)
		.expect("owner drop releases stage lease despite retained duplicate");
	flock(&contender, FlockOperation::Unlock).expect("release contender lease");
	drop(root);

	let replacement = fixture.bind();
	open_staging(&replacement);
	drop((root_alias, child_alias));
}

#[test]
fn foreign_process_cannot_use_the_lease_or_unlock_a_retained_description() {
	let fixture = Fixture::new();
	let mut root = fixture.bind();
	let alias = root
		.lease
		.file
		.try_clone()
		.expect("retain the creator's open description");
	// Darwin reserves PID zero for the kernel. Set a different recorded PID
	// without running non-async-signal-safe Rust in a post-fork test child.
	root.lease.lease_process = 0;
	assert!(matches!(
		root.open_stage_directory(name(b"private-stage")),
		Err(StageError::WrongProcess)
	));
	drop(root);

	let contender = File::open(fixture.path(".")).expect("open independent destination contender");
	assert_eq!(
		flock(&contender, FlockOperation::NonBlockingLockExclusive),
		Err(Errno::AGAIN)
	);
	flock(&alias, FlockOperation::Unlock).expect("release retained lease as the test owner");
	fixture.bind();
}

#[test]
fn native_attempts_for_one_job_entry_epoch_and_target_have_distinct_bindings() {
	use super::super::tests::context;

	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let target = name(b"unpublished");
	let context = context();
	let first = directory
		.create_file(name(b"native-attempt-one"), target, context, 0)
		.unwrap();
	let second = directory
		.create_file(name(b"native-attempt-two"), target, context, 0)
		.unwrap();
	assert_ne!(
		first.identity().stage_id_bytes(),
		second.identity().stage_id_bytes()
	);
	assert_ne!(first.binding(), second.binding());

	let first = first.flush_and_close().unwrap();
	let second = second.flush_and_close().unwrap();
	assert_ne!(first.binding(), second.binding());
	assert_eq!(first.target(), target);
	assert_eq!(second.target(), target);
	assert!(!fixture.path("unpublished").exists());
}

#[test]
fn entropy_failure_has_no_private_create_effect() {
	use std::fs;
	use std::io;

	use super::super::tests::context;

	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let error = directory
		.create_file_with_entropy(
			name(b"no-entropy"),
			name(b"unpublished"),
			context(),
			0,
			|bytes| {
				bytes[0] = 0xAC;
				Err(io::Error::from_raw_os_error(libc::EIO))
			},
		)
		.unwrap_err();

	assert!(
		matches!(error, StageError::EntropyUnavailable(error) if error.raw_os_error() == Some(libc::EIO))
	);
	assert_eq!(
		fs::read_dir(fixture.path("private-stage")).unwrap().count(),
		0
	);
	assert!(!fixture.path("unpublished").exists());
}

#[test]
fn uncertain_native_create_error_keeps_the_allocated_identity() {
	use std::fs::{self, Permissions};
	use std::os::unix::fs::PermissionsExt as _;

	use super::super::tests::context;
	use super::RANDOM_STAGE_ID_BYTES;

	const INJECTED_ENTROPY: [u8; RANDOM_STAGE_ID_BYTES] = [0x4D; RANDOM_STAGE_ID_BYTES];
	let fixture = Fixture::new();
	let root = fixture.bind();
	let directory = open_staging(&root);
	let private = fixture.path("private-stage");
	let error = directory
		.create_file_with_entropy(
			name(b"uncertain-create"),
			name(b"unpublished"),
			context(),
			0,
			|bytes| {
				*bytes = INJECTED_ENTROPY;
				fs::set_permissions(&private, Permissions::from_mode(0o500))
			},
		)
		.unwrap_err();
	fs::set_permissions(&private, Permissions::from_mode(0o700)).unwrap();

	let StageError::CreateUncertain { identity, source } = error else {
		panic!("expected an attempt identity for reconciliation, got {error:?}");
	};
	assert_eq!(
		&identity.stage_id_bytes()[..RANDOM_STAGE_ID_BYTES],
		&INJECTED_ENTROPY
	);
	assert!(
		matches!(*source, StageError::System(error) if error.kind() == std::io::ErrorKind::PermissionDenied)
	);
	assert!(!fixture.path("unpublished").exists());
}
