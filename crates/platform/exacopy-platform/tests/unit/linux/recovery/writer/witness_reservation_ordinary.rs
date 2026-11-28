use std::fs::{File, Permissions};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use exacopy_endpoint::UnixComponent;

use crate::linux::{DestinationRoot, ReadError, StageError};
use crate::scratch::Scratch;

use super::{FIRST_SEGMENT, JOURNAL, native};

const OLD_BYTES: &[u8; 8] = b"old head";

#[test]
fn held_segment_distinguishes_writer_position_from_changed_file_extent() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let name = UnixComponent::new(b"reservation-position").unwrap();
	{
		let job = root.create_job_directory(name).unwrap();
		let directory = job.create_journal_directory().unwrap();
		let mut segment = directory.create_first_segment().unwrap();
		segment.write_all(OLD_BYTES).unwrap();
	}
	let job = root.open_recovery_job(name).unwrap();
	let lease = root.try_recovery_write_lease(name, job.identity()).unwrap();
	let readback = lease.job().open_first_segment().unwrap();
	let mut held = lease.hold_first_segment_for_append(&readback).unwrap();
	let accepted_end = 8;
	assert_eq!(readback.len(), accepted_end);
	let inode = held.file.metadata().unwrap().ino();
	held.recheck(&lease, &readback).unwrap();

	// Moving the held writer cursor leaves the bytes and inode unchanged.
	held.file.rewind().unwrap();
	assert!(matches!(
		held.recheck(&lease, &readback),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(held.file.stream_position().unwrap(), 0);
	let mut bytes = [0; OLD_BYTES.len()];
	readback.read_exact_at(0, &mut bytes).unwrap();
	assert_eq!(&bytes, OLD_BYTES);

	held.file.seek(SeekFrom::Start(accepted_end)).unwrap();
	held.recheck(&lease, &readback).unwrap();

	// Truncating the owned fixture changes its extent without moving the writer.
	held.file.set_len(accepted_end - 1).unwrap();
	assert_eq!(held.file.stream_position().unwrap(), accepted_end);
	assert!(matches!(
		held.recheck(&lease, &readback),
		Err(StageError::ReadBack(ReadError::SourceChanged))
	));
	let path = scratch
		.path("reservation-position")
		.join(JOURNAL)
		.join(FIRST_SEGMENT);
	assert_eq!(path.metadata().unwrap().ino(), inode);
	assert_eq!(std::fs::read(path).unwrap(), b"old hea");
}

#[test]
fn anonymous_receipt_probe_requires_same_mount_and_empty_unlinked_inode() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let path = scratch.path("receipt-probe");
	let mut file = File::options()
		.create_new(true)
		.read(true)
		.write(true)
		.open(&path)
		.unwrap();
	// A set-group-ID parent or grpid mount may choose a different group.
	let group = rustix::process::getegid();
	if file.metadata().unwrap().gid() != group.as_raw() {
		rustix::fs::fchown(&file, None, Some(group)).unwrap();
	}
	file.set_permissions(Permissions::from_mode(0o600)).unwrap();
	std::fs::remove_file(&path).unwrap();

	let metadata = file.metadata().unwrap();
	assert_eq!(metadata.nlink(), 0);
	let observed = native::inspect_anonymous(&file, root.mount).unwrap();
	assert_eq!(observed.identity().inode(), metadata.ino());
	assert_eq!(observed.identity().device(), metadata.dev());
	assert!(observed.is_empty());
	assert!(matches!(
		native::inspect_anonymous(&file, root.mount ^ 1),
		Err(StageError::IdentityChanged)
	));

	file.write_all(b"x").unwrap();
	assert!(matches!(
		native::inspect_anonymous(&file, root.mount),
		Err(StageError::UnsafeFile)
	));
	file.rewind().unwrap();
	let mut byte = [0];
	file.read_exact(&mut byte).unwrap();
	assert_eq!(&byte, b"x");
	assert_eq!(file.read(&mut byte).unwrap(), 0);
	assert_eq!(file.metadata().unwrap().ino(), metadata.ino());
	assert_eq!(
		path.symlink_metadata().unwrap_err().kind(),
		io::ErrorKind::NotFound
	);
}
