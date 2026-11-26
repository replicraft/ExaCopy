use std::io::{Read as _, Write as _};

use exacopy_endpoint::UnixComponent;

use crate::linux::DestinationRoot;
use crate::scratch::Scratch;

use super::super::{ReservedJournalRead, native};
use super::{append_held, observe_successor};

#[test]
#[ignore = "requires a task-owned Linux fixture supporting KEEP_SIZE"]
fn original_reserved_descriptor_writes_and_rereads_only_the_exact_successor() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let name = UnixComponent::new(b"continued-custody").unwrap();
	let old = b"authenticated prior transcript";
	let successor = b"one bounded canonical transition supplied by application";
	let job = root.create_job_directory(name).unwrap();
	let directory = job.create_journal_directory().unwrap();
	let mut segment = directory.create_first_segment().unwrap();
	segment.write_all(old).unwrap();
	drop(segment);
	drop(directory);
	drop(job);

	let id = root.open_recovery_job(name).unwrap().identity();
	let lease = root.try_recovery_write_lease(name, id).unwrap();
	let expected = lease.job().open_first_segment().unwrap();
	let mut held = lease.hold_first_segment_for_append(&expected).unwrap();
	let descriptor = std::os::fd::AsRawFd::as_raw_fd(&held.file);
	native::allocate(&held.file, expected.len(), 8_192).unwrap();
	let expected = lease.job().open_first_segment().unwrap();
	held.recheck(&lease, &expected).unwrap();
	assert!(lease.open_first_segment_for_append(&expected).is_err());

	append_held(&mut held, successor, ()).unwrap();
	let end = expected.len() + successor.len() as u64;
	assert_eq!(std::os::fd::AsRawFd::as_raw_fd(&held.file), descriptor);
	assert!(
		observe_successor(&held, &lease, &expected, expected.len(), end - 1, successor).is_err()
	);
	let mut incorrect = successor.to_vec();
	incorrect[0] ^= 1;
	assert!(observe_successor(&held, &lease, &expected, expected.len(), end, &incorrect).is_err());
	let accepted =
		observe_successor(&held, &lease, &expected, expected.len(), end, successor).unwrap();
	assert_eq!(accepted.identity(), expected.identity());
	let mut readback = ReservedJournalRead {
		readback: &accepted,
		offset: 0,
		_same_lane: std::marker::PhantomData,
	};
	let mut bytes = Vec::new();
	readback.read_to_end(&mut bytes).unwrap();
	assert_eq!(&bytes[..old.len()], old);
	assert_eq!(&bytes[old.len()..], successor);
	assert_eq!(readback.read(&mut [0]).unwrap(), 0);
}
