use std::io::Write as _;
use std::path::Path;

use exacopy_endpoint::IoError;
use rustix::fs as native;
use rustix::io::Errno;

use super::super::{
	FlockOperation, HeldDirectory, MAX_PROTECTED_SNAPSHOT_BYTES, ProtectedSnapshotError, ReadError,
	UnixComponent, protected_length, read_error, read_twice_into,
};
use super::{FILE, create_fixture};
use crate::read_protected_snapshot_into;
use crate::scratch::Scratch;

#[test]
fn caller_buffer_snapshot_requires_nonempty_readback_storage() {
	let mut bytes = [0x31; 8];
	assert_eq!(
		read_protected_snapshot_into(Path::new("relative"), &mut bytes, &mut []),
		Err(ProtectedSnapshotError::Unavailable)
	);
	assert_eq!(bytes, [0x31; 8], "refusal must precede writes to output");
}

#[test]
fn a_held_private_file_checks_owner_and_exact_snapshot_size_limit() {
	for (length, expected) in [
		(
			MAX_PROTECTED_SNAPSHOT_BYTES,
			Ok(MAX_PROTECTED_SNAPSHOT_BYTES),
		),
		(
			MAX_PROTECTED_SNAPSHOT_BYTES + 1,
			Err(ProtectedSnapshotError::TooLarge),
		),
	] {
		let scratch = Scratch::new();
		create_fixture(&scratch)
			.set_len(u64::try_from(length).expect("fixture length fits in u64"))
			.expect("set the logical length of the fixture");
		let owner = rustix::process::geteuid().as_raw();
		let parent =
			HeldDirectory::new(scratch.open().into(), owner).expect("observe the fixture parent");
		let root = parent
			.lock_private(owner)
			.expect("lease the fixture parent");
		let name = UnixComponent::new(FILE.as_bytes()).expect("validate the fixture name");
		let file = root
			.open_regular(name)
			.expect("hold the selected fixture file");

		assert_eq!(protected_length(&file, owner), expected, "length {length}");
		assert_eq!(
			protected_length(&file, owner ^ 1),
			Err(ProtectedSnapshotError::Unprotected),
			"a different requested owner must fail before size admission"
		);
	}
}

#[test]
fn held_snapshot_readback_visits_every_chunk_and_bounds_the_final_write() {
	let scratch = Scratch::new();
	let expected = b"ABCDwxyz!";
	create_fixture(&scratch)
		.write_all(expected)
		.expect("write the synthetic snapshot");
	let owner = rustix::process::geteuid().as_raw();
	let parent =
		HeldDirectory::new(scratch.open().into(), owner).expect("observe the fixture parent");
	let root = parent
		.lock_private(owner)
		.expect("lease the fixture parent");
	let name = UnixComponent::new(FILE.as_bytes()).expect("validate the fixture name");
	let file = root
		.open_regular(name)
		.expect("hold the selected fixture file");
	let length = protected_length(&file, owner).expect("admit the fixture byte length");
	assert_eq!(length, expected.len());

	let mut bytes = [0x31; 9];
	let mut readback = [0x32; 4];
	read_twice_into(&root, name, &file, &mut bytes, &mut readback)
		.expect("both held reads must agree over the full fixture length");
	assert_eq!(&bytes, expected);
	assert_eq!(
		&readback, b"!xyz",
		"the short final chunk owns only the first byte of the readback buffer"
	);
}

#[test]
fn held_read_faults_preserve_protected_snapshot_refusals() {
	for (fault, expected) in [
		(
			ReadError::UnexpectedDataAfterEnd,
			ProtectedSnapshotError::Changed,
		),
		(
			ReadError::Io(IoError::UnexpectedEof { offset: 4 }),
			ProtectedSnapshotError::Changed,
		),
		(
			ReadError::NotRegularFile,
			ProtectedSnapshotError::Unprotected,
		),
		(
			ReadError::UnsupportedProcfs,
			ProtectedSnapshotError::Unsupported,
		),
		(
			ReadError::System(Errno::XDEV.into()),
			ProtectedSnapshotError::Unsupported,
		),
		(
			ReadError::System(Errno::NOENT.into()),
			ProtectedSnapshotError::Unavailable,
		),
		(
			ReadError::InvalidTimestamp,
			ProtectedSnapshotError::Unavailable,
		),
	] {
		let description = fault.to_string();
		assert_eq!(read_error(fault), expected, "{description}");
	}
}

#[test]
fn an_exclusive_parent_lease_blocks_snapshot_reading_until_release() {
	let scratch = Scratch::new();
	let owner = rustix::process::geteuid().as_raw();
	let parent =
		HeldDirectory::new(scratch.open().into(), owner).expect("observe the fixture parent");
	let writer = scratch.open();
	native::flock(&writer, FlockOperation::NonBlockingLockExclusive)
		.expect("lock the fixture parent for the cooperating writer");

	assert!(
		matches!(
			parent.lock_private(owner),
			Err(ProtectedSnapshotError::Busy)
		),
		"a cooperating writer must block acquisition of the reader lease"
	);
	drop(writer);
	let _reader = parent
		.lock_private(owner)
		.expect("acquire the reader lease after the writer releases it");
}
