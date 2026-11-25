use std::fs::{self, File};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};
use std::path::Path;

use rustix::fs::{FlockOperation, flock};
use rustix::io::Errno;

use super::super::tests::{Fixture, make_stage, name, open_staging};
use super::{ManagedReadError, ManagedReadGrant, StageError};
use crate::macos::ManagedReadRoot;

fn grant() -> ManagedReadGrant {
	ManagedReadGrant::trusted_owner_authorizes_provisioned_root()
}

fn create_source(path: &Path, bytes: &[u8]) {
	File::options()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(path)
		.expect("create an authorized synthetic source")
		.write_all(bytes)
		.expect("write source fixture");
}

#[test]
fn authorized_source_and_private_stage_share_an_exclusive_destination_lease() {
	let fixture = Fixture::new();
	let source_path = fixture.path("source");
	const PAYLOAD: &[u8] = b"separately authorized source";
	create_source(&source_path, PAYLOAD);
	let parent = source_path.parent().expect("source fixture parent");
	let root = fixture.bind();
	let source = root
		.open_regular_source(parent, name(b"source"), grant())
		.expect("borrow the destination lease for an independently authorized source");

	assert!(matches!(
		ManagedReadRoot::open_provisioned_path(parent, grant()),
		Err(ManagedReadError::DirectoryBusy)
	));
	{
		let directory = open_staging(&root);
		let mut copy = [0; PAYLOAD.len()];
		source
			.read_exact_at(0, &mut copy)
			.expect("read source exactly");
		assert_eq!(&copy, PAYLOAD);
		let mut writer =
			make_stage(&directory, source.length()).expect("create a new private stage");
		writer
			.write_next(&copy)
			.expect("write source bytes to stage");
		let closed = writer
			.flush_and_close()
			.expect("synchronize and close stage");
		let read_back = closed.open_read_back().expect("reopen private stage");
		read_back
			.read_exact_at(0, &mut copy)
			.expect("read back private stage");
		read_back
			.revalidate()
			.expect("revalidate stage after read-back");
		assert_eq!(&copy, PAYLOAD);
		source
			.revalidate()
			.expect("source remained stable during staging");
		assert_eq!(
			fs::read(&source_path).expect("inspect source fixture"),
			PAYLOAD
		);
		assert!(!fixture.path("target").exists());
	}

	drop(source);
	assert!(matches!(
		ManagedReadRoot::open_provisioned_path(parent, grant()),
		Err(ManagedReadError::DirectoryBusy)
	));
	drop(root);
	ManagedReadRoot::open_provisioned_path(parent, grant()).expect("root drop releases lease");
}

#[test]
fn source_parent_requires_positive_identity_and_no_symlink() {
	let destination = Fixture::new();
	let source = Fixture::new();
	let source_path = source.path("source");
	create_source(&source_path, b"other directory");
	create_source(&destination.path("source"), b"destination directory");
	let root = destination.bind();
	let other_parent = source_path.parent().expect("source fixture parent");
	assert!(matches!(
		root.open_regular_source(other_parent, name(b"source"), grant()),
		Err(ManagedReadError::UnsupportedNamespace)
	));

	let destination_path = destination.path("source");
	let destination_parent = destination_path
		.parent()
		.expect("destination fixture parent");
	let alias = source.path("parent-link");
	symlink(destination_parent, &alias).expect("make alias to exact destination parent");
	assert!(matches!(
		root.open_regular_source(&alias, name(b"source"), grant()),
		Err(ManagedReadError::System(_))
	));
}

#[test]
fn borrowed_read_refuses_symbolic_and_hard_links() {
	let fixture = Fixture::new();
	let source_path = fixture.path("source");
	create_source(&source_path, b"original bytes");
	let parent = source_path.parent().expect("source fixture parent");
	symlink(&source_path, fixture.path("source-link")).expect("make source symlink");
	fs::hard_link(&source_path, fixture.path("other-link")).expect("make source hard link");
	let root = fixture.bind();
	for name_bytes in [b"source-link".as_slice(), b"source", b"other-link"] {
		assert!(matches!(
			root.open_regular_source(parent, name(name_bytes), grant()),
			Err(ManagedReadError::UnsupportedChild)
		));
	}
}

#[test]
fn borrowed_reader_rechecks_the_acquiring_process_and_directory_authority() {
	let fixture = Fixture::new();
	let source_path = fixture.path("source");
	create_source(&source_path, b"source bytes");
	let parent = source_path.parent().expect("source fixture parent");
	let mut root = fixture.bind();
	let acquired = root.lease.lease_process;
	// Darwin reserves PID zero for the kernel. Exercise process refusal without forking.
	root.lease.lease_process = 0;
	assert!(matches!(
		root.open_regular_source(parent, name(b"source"), grant()),
		Err(ManagedReadError::UnsupportedNamespace)
	));
	root.lease.lease_process = acquired;

	let source = root
		.open_regular_source(parent, name(b"source"), grant())
		.unwrap();
	// Deliberately violate the fixture's managed-root contract to test read-time revalidation.
	fs::set_permissions(parent, fs::Permissions::from_mode(0o750)).unwrap();
	let mut buffer = [0; 1];
	assert!(matches!(
		source.read_exact_at(0, &mut buffer),
		Err(ManagedReadError::UnsupportedNamespace)
	));
	assert_eq!(buffer, [0]);
	assert!(matches!(
		source.revalidate(),
		Err(ManagedReadError::UnsupportedNamespace)
	));
}

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
