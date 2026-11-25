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
