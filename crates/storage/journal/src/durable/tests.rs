use std::fs::{self, File};
use std::io::{self, Seek as _, SeekFrom, Write as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::{DurableJournal, DurableJournalError};
use crate::frame::{ChainHead, FrameKind, FrameReader, FrameWriteError, MAX_PAYLOAD_BYTES};

const OWNER_PAYLOAD: &[u8] = b"fixture owner record";
const INTENT_PAYLOAD: &[u8] = b"fixture intent record";

#[test]
fn synced_frames_are_visible_from_a_separate_read_handle() {
	let (scratch, file) = ScratchFile::create();
	let mut journal = DurableJournal::from_new_file(file).expect("admit exclusive empty file");
	let first = journal
		.append(FrameKind::JobPrepared, OWNER_PAYLOAD)
		.expect("append and sync owner frame");
	let second = journal
		.append(FrameKind::PublishIntent, INTENT_PAYLOAD)
		.expect("append and sync intent frame");

	let mut reader = scratch.reader();
	let owner = reader
		.next_frame()
		.expect("valid owner frame")
		.expect("owner frame is present");
	assert_eq!(owner.kind(), first.kind());
	assert_eq!(owner.head(), first.head());
	assert_eq!(owner.payload(), OWNER_PAYLOAD);
	let intent = reader
		.next_frame()
		.expect("valid intent frame")
		.expect("intent frame is present");
	assert_eq!(intent.kind(), second.kind());
	assert_eq!(intent.head(), second.head());
	assert_eq!(intent.payload(), INTENT_PAYLOAD);
	assert_eq!(intent.previous_digest(), first.head().digest());
	assert_eq!(reader.next_frame().expect("clean journal end"), None);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn barrier_errors_permanently_retire_the_writer_and_keep_the_complete_frame() {
	// POSIX error numbers on these test platforms.
	const EIO: i32 = 5;
	const ENOSPC: i32 = 28;
	for errno in [EIO, ENOSPC] {
		let (scratch, file) = ScratchFile::create();
		let mut journal = DurableJournal::from_new_file(file).expect("admit exclusive empty file");
		let owner = journal
			.append(FrameKind::JobPrepared, OWNER_PAYLOAD)
			.expect("sync preceding frame before fault");
		let result = journal.append_with_barrier(FrameKind::PublishIntent, INTENT_PAYLOAD, |_| {
			let mut reader = scratch.reader();
			let first = reader
				.next_frame()
				.expect("valid preceding frame at barrier entry")
				.expect("preceding frame is present");
			assert_eq!(first.head(), owner.head());
			let second = reader
				.next_frame()
				.expect("frame must be complete before barrier")
				.expect("frame is present before barrier");
			assert_eq!(second.kind(), FrameKind::PublishIntent);
			assert_eq!(second.payload(), INTENT_PAYLOAD);
			assert_eq!(reader.next_frame().expect("clean boundary"), None);
			Err(io::Error::from_raw_os_error(errno))
		});
		assert!(matches!(
			result,
			Err(DurableJournalError::Sync(source)) if source.raw_os_error() == Some(errno)
		));
		let preserved = scratch.bytes();
		assert!(matches!(
			journal.append_with_barrier(FrameKind::PublishIntent, INTENT_PAYLOAD, |_| {
				panic!("retired writer reached another barrier after error {errno}");
			}),
			Err(DurableJournalError::Retired)
		));
		assert_eq!(
			scratch.bytes(),
			preserved,
			"retry changed evidence for {errno}"
		);
	}
}

#[test]
fn a_write_error_retires_the_writer_before_the_barrier() {
	let (scratch, file) = ScratchFile::create();
	drop(file);
	let readonly = File::open(&scratch.0).expect("open a read-only fixture handle");
	let mut journal = DurableJournal::from_new_file(readonly).expect("inspect empty fixture");
	assert!(matches!(
		journal.append_with_barrier(FrameKind::JobPrepared, OWNER_PAYLOAD, |_| {
			panic!("failed write must stop before the barrier");
		}),
		Err(DurableJournalError::Frame(FrameWriteError::Io(_)))
	));
	assert!(matches!(
		journal.append(FrameKind::JobPrepared, OWNER_PAYLOAD),
		Err(DurableJournalError::Retired)
	));
	assert!(
		scratch.bytes().is_empty(),
		"read-only file unexpectedly changed"
	);
}

#[test]
fn rejecting_an_oversized_payload_leaves_the_writer_at_its_boundary() {
	let (scratch, file) = ScratchFile::create();
	let mut journal = DurableJournal::from_new_file(file).expect("admit exclusive empty file");
	let oversized = vec![0; MAX_PAYLOAD_BYTES + 1];
	assert!(matches!(
		journal.append_with_barrier(FrameKind::JobPrepared, &oversized, |_| {
			panic!("invalid frame must stop before the barrier");
		}),
		Err(DurableJournalError::Frame(
			FrameWriteError::PayloadTooLarge(_)
		))
	));
	assert!(scratch.bytes().is_empty(), "invalid input reached the file");
	let synced = journal
		.append(FrameKind::JobPrepared, OWNER_PAYLOAD)
		.expect("valid append after an input rejection");
	assert_eq!(synced.head().sequence(), 1);
}

#[test]
fn admission_rejects_nonempty_files_without_changing_them() {
	let (scratch, mut file) = ScratchFile::create();
	file.write_all(b"existing").expect("seed incumbent bytes");
	file.rewind().expect("return the cursor to the start");
	assert!(matches!(
		DurableJournal::from_new_file(file),
		Err(DurableJournalError::UnexpectedLength {
			expected: 0,
			actual: 8
		})
	));
	assert_eq!(scratch.bytes(), b"existing");
}

#[test]
fn admission_rejects_a_cursor_past_the_empty_boundary() {
	let (scratch, mut file) = ScratchFile::create();
	file.seek(SeekFrom::Start(1))
		.expect("move fixture's cursor");
	assert!(matches!(
		DurableJournal::from_new_file(file),
		Err(DurableJournalError::UnexpectedCursor {
			expected: 0,
			actual: 1
		})
	));
	assert!(
		scratch.bytes().is_empty(),
		"stale cursor created a sparse file"
	);
}

#[cfg(unix)]
#[test]
fn admission_rejects_a_directory_handle() {
	let file = File::open(std::env::temp_dir()).expect("open fixture directory handle");
	assert!(matches!(
		DurableJournal::from_new_file(file),
		Err(DurableJournalError::NotRegularFile)
	));
}

#[test]
fn changed_boundary_before_append_retires_the_writer() {
	let (scratch, file) = ScratchFile::create();
	let alias = file
		.try_clone()
		.expect("create a fixture-only duplicate writer");
	let mut journal = DurableJournal::from_new_file(file).expect("admit initially empty file");
	let synced = journal
		.append(FrameKind::JobPrepared, OWNER_PAYLOAD)
		.expect("sync frame before out-of-band change");
	let original_len = alias.metadata().expect("observe fixture length").len();
	alias
		.set_len(original_len + 1)
		.expect("extend fixture out of band");
	let changed = scratch.bytes();
	assert!(matches!(
		journal.append(FrameKind::PublishIntent, INTENT_PAYLOAD),
		Err(DurableJournalError::UnexpectedLength { expected, actual })
			if expected == original_len && actual == original_len + 1
	));
	assert!(matches!(
		journal.append(FrameKind::PublishIntent, INTENT_PAYLOAD),
		Err(DurableJournalError::Retired)
	));
	assert_eq!(
		scratch.bytes(),
		changed,
		"append disturbed the unexpected suffix"
	);
	let mut reader = scratch.reader();
	let frame = reader
		.next_frame()
		.expect("valid synced prefix")
		.expect("frame present");
	assert_eq!(frame.head(), synced.head());
}

struct ScratchFile(PathBuf);

impl ScratchFile {
	fn create() -> (Self, File) {
		static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);
		const MAX_ATTEMPTS: usize = 128;
		for _ in 0..MAX_ATTEMPTS {
			let attempt = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
			let path = std::env::temp_dir().join(format!(
				"exacopy-journal-test-{}-{attempt}",
				std::process::id()
			));
			match File::create_new(&path) {
				Ok(file) => return (Self(path), file),
				Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
				Err(error) => panic!("could not create a synthetic journal file: {error}"),
			}
		}
		panic!("could not acquire an exclusive synthetic journal file");
	}

	fn bytes(&self) -> Vec<u8> {
		fs::read(&self.0).expect("read journal bytes independently")
	}

	fn reader(&self) -> FrameReader<File> {
		let read_handle = File::open(&self.0).expect("open journal for independent read");
		FrameReader::new(read_handle, ChainHead::start())
	}
}

impl Drop for ScratchFile {
	fn drop(&mut self) {
		let _ = fs::remove_file(&self.0);
	}
}
