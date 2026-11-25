use std::cell::Cell;
use std::fs::{self, File};
use std::io::{self, Seek as _, SeekFrom, Write as _};

use super::{DurableJournal, DurableJournalError, JournalFileBarrier, MAX_FIRST_SEGMENT_BYTES};
use crate::frame::{
	ChainHead, FRAME_OVERHEAD_BYTES, FrameKind, FrameReadError, FrameReader, FrameWriteError,
	FrameWriter, MAX_PAYLOAD_BYTES,
};

mod darwin;
mod fixture;
mod memory;

use self::fixture::{ScratchFile, TestSegment};

const OWNER_PAYLOAD: &[u8] = b"fixture owner record";
const INTENT_PAYLOAD: &[u8] = b"fixture intent record";

#[test]
fn synced_frames_are_visible_from_a_separate_read_handle() {
	let (scratch, file) = ScratchFile::create();
	let mut journal = DurableJournal::from_new_segment(TestSegment::held(file))
		.expect("admit exclusive empty file");
	let first = journal
		.append(FrameKind::JobPrepared, OWNER_PAYLOAD)
		.expect("append and sync owner frame");
	assert_eq!(first.barrier(), JournalFileBarrier::SyncAll);
	let (record, second) = journal
		.append_frame(FrameKind::PublishIntent, INTENT_PAYLOAD.to_vec())
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
	assert_eq!(intent, record);
	assert_eq!(intent.kind(), second.kind());
	assert_eq!(intent.head(), second.head());
	assert_eq!(intent.payload(), INTENT_PAYLOAD);
	assert_eq!(intent.previous_digest(), first.head().digest());
	assert_eq!(reader.next_frame().expect("clean journal end"), None);
}

#[test]
fn resuming_a_clean_segment_appends_to_the_verified_chain() {
	let (scratch, head, end) = synced_owner();
	let prefix = scratch.bytes();
	let mut file = scratch.reopen();
	file.seek(SeekFrom::Start(end + 1))
		.expect("seed an unrelated descriptor cursor");
	let mut journal = DurableJournal::resume_first_segment(TestSegment::held(file), head, end)
		.expect("resume the exact verified journal prefix");
	assert_eq!(scratch.bytes(), prefix);
	let appended = journal
		.append(FrameKind::PublishIntent, INTENT_PAYLOAD)
		.expect("append and sync a frame on the resumed writer");
	assert_eq!(appended.head().sequence(), head.sequence() + 1);
	assert!(scratch.bytes().starts_with(&prefix));

	let mut reader = scratch.reader();
	let first = reader
		.next_frame()
		.expect("read owner")
		.expect("owner frame");
	assert_eq!(first.head(), head);
	let second = reader
		.next_frame()
		.expect("read intent")
		.expect("intent frame");
	assert_eq!(second.previous_digest(), head.digest());
	assert_eq!(second.head(), appended.head());
	assert_eq!(reader.next_frame().expect("clean end"), None);
}

#[test]
fn resumption_requires_the_digest_even_for_equal_length_and_sequence() {
	let (scratch, expected_head, expected_end) = synced_owner();
	let (foreign, file) = ScratchFile::create();
	let mut foreign_journal =
		DurableJournal::from_new_segment(TestSegment::held(file)).expect("admit foreign file");
	let payload = vec![b'x'; OWNER_PAYLOAD.len()];
	let head = foreign_journal
		.append(FrameKind::JobPrepared, &payload)
		.expect("sync the foreign frame")
		.head();
	drop(foreign_journal);
	let prefix = foreign.bytes();
	assert_eq!(prefix.len(), scratch.bytes().len());
	assert_eq!(head.sequence(), expected_head.sequence());
	assert_ne!(head.digest(), expected_head.digest());
	assert!(matches!(
		DurableJournal::resume_first_segment(
			TestSegment::with_barrier(foreign.reopen(), |_| {
				panic!("a different digest reached the barrier")
			}),
			expected_head,
			expected_end
		),
		Err(DurableJournalError::UnexpectedHead)
	));
	assert_eq!(foreign.bytes(), prefix);
}

#[test]
fn resumption_rereads_the_prefix_before_the_expected_head() {
	let (scratch, first, end) = synced_owner();
	let mut journal =
		DurableJournal::resume_first_segment(TestSegment::held(scratch.reopen()), first, end)
			.expect("resume before adding the final frame");
	let last = journal
		.append(FrameKind::PublishIntent, INTENT_PAYLOAD)
		.expect("sync the final frame")
		.head();
	drop(journal);
	let mut file = scratch.reopen();
	let length = file.metadata().expect("inspect fixture length").len();
	file.write_all(b"!")
		.expect("damage the first frame's magic");
	let damaged = scratch.bytes();
	assert!(damaged.ends_with(&last.digest()));
	assert!(matches!(
		DurableJournal::resume_first_segment(
			TestSegment::with_barrier(file, |_| {
				panic!("an earlier corrupt frame reached the barrier")
			}),
			last,
			length
		),
		Err(DurableJournalError::ReadFrame(FrameReadError::Corrupt {
			offset: 0,
			..
		}))
	));
	assert_eq!(scratch.bytes(), damaged);
}

#[test]
fn resumption_preserves_a_torn_or_corrupt_suffix() {
	let (scratch, head, end) = synced_owner();
	for (suffix, torn) in [(b"EXA".as_slice(), true), (b"wrong".as_slice(), false)] {
		let mut file = scratch.reopen();
		file.set_len(end).expect("restore the fixture prefix");
		file.seek(SeekFrom::Start(end))
			.expect("seek to the prefix end");
		file.write_all(suffix).expect("seed an invalid suffix");
		let length = file.metadata().expect("inspect fixture length").len();
		let original = scratch.bytes();
		assert!(matches!(
			DurableJournal::resume_first_segment(TestSegment::held(scratch.reopen()), head, end),
			Err(DurableJournalError::UnexpectedLength { expected, actual })
				if expected == end && actual == length
		));
		let result = DurableJournal::resume_first_segment(
			TestSegment::with_barrier(file, |_| panic!("an invalid suffix reached the barrier")),
			head,
			length,
		);
		if torn {
			assert!(
				matches!(result, Err(DurableJournalError::ReadFrame(FrameReadError::TornTail { offset, .. })) if offset == end)
			);
		} else {
			assert!(
				matches!(result, Err(DurableJournalError::ReadFrame(FrameReadError::Corrupt { offset, .. })) if offset == end)
			);
		}
		assert_eq!(scratch.bytes(), original);
	}
}

#[test]
fn resumption_requires_a_nonempty_prefix_within_the_segment_limit() {
	let (scratch, file) = ScratchFile::create();
	assert!(matches!(
		DurableJournal::resume_first_segment(TestSegment::held(file), ChainHead::start(), 0),
		Err(DurableJournalError::EmptyPrefix)
	));
	assert!(scratch.bytes().is_empty());
	let (scratch, head, _) = synced_owner();
	let file = scratch.reopen();
	let length = MAX_FIRST_SEGMENT_BYTES + 1;
	file.set_len(length).expect("seed an oversized sparse file");
	assert!(matches!(
		DurableJournal::resume_first_segment(TestSegment::held(file), head, length),
		Err(DurableJournalError::SegmentTooLarge { length: actual, limit })
			if actual == length && limit == MAX_FIRST_SEGMENT_BYTES
	));
	assert_eq!(
		scratch.reopen().metadata().expect("inspect size").len(),
		length
	);
	assert_eq!(
		scratch
			.reader()
			.next_frame()
			.expect("read")
			.expect("owner")
			.head(),
		head
	);
}

#[cfg(unix)]
#[test]
fn resumption_rejects_a_directory_handle() {
	let (_scratch, head, end) = synced_owner();
	let directory = File::open(std::env::temp_dir()).expect("open fixture directory handle");
	assert!(matches!(
		DurableJournal::resume_first_segment(TestSegment::held(directory), head, end),
		Err(DurableJournalError::NotRegularFile)
	));
}

#[test]
fn resumption_requires_successful_reads_and_a_successful_barrier() {
	let (scratch, head, end) = synced_owner();
	let prefix = scratch.bytes();
	let write_only = File::options()
		.write(true)
		.open(&scratch.0)
		.expect("open write-only fixture");
	assert!(matches!(
		DurableJournal::resume_first_segment(
			TestSegment::with_barrier(write_only, |_| {
				panic!("a failed read reached the barrier")
			}),
			head,
			end
		),
		Err(DurableJournalError::ReadFrame(FrameReadError::Io {
			offset: 0,
			..
		}))
	));
	assert_eq!(scratch.bytes(), prefix);
	assert!(matches!(
		DurableJournal::resume_first_segment(TestSegment::with_barrier(scratch.reopen(), |file| {
			assert_eq!(file.metadata().expect("inspect file at barrier").len(), end);
			assert_eq!(scratch.bytes(), prefix);
			Err(io::Error::other("injected resume barrier failure"))
		}), head, end),
		Err(DurableJournalError::Sync(source)) if source.kind() == io::ErrorKind::Other
	));
	assert_eq!(scratch.bytes(), prefix);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn barrier_errors_permanently_retire_the_writer_and_keep_the_complete_frame() {
	// POSIX error numbers on these test platforms.
	const EIO: i32 = 5;
	const ENOSPC: i32 = 28;
	for errno in [EIO, ENOSPC] {
		let (scratch, file) = ScratchFile::create();
		let barriers = Cell::new(0);
		let owner_head = Cell::new(ChainHead::start());
		let segment = TestSegment::with_barrier(file, |file| {
			barriers.set(barriers.get() + 1);
			if barriers.get() == 1 {
				return file.sync_all();
			}
			assert_eq!(barriers.get(), 2, "retired writer entered the barrier");
			let mut reader = scratch.reader();
			let first = reader
				.next_frame()
				.expect("valid preceding frame at barrier entry")
				.expect("preceding frame is present");
			assert_eq!(first.head(), owner_head.get());
			let second = reader
				.next_frame()
				.expect("frame must be complete before barrier")
				.expect("frame is present before barrier");
			assert_eq!(second.kind(), FrameKind::PublishIntent);
			assert_eq!(second.payload(), INTENT_PAYLOAD);
			assert_eq!(reader.next_frame().expect("clean boundary"), None);
			Err(io::Error::from_raw_os_error(errno))
		});
		let mut journal = DurableJournal::from_new_segment(segment).expect("admit owned segment");
		let owner = journal
			.append(FrameKind::JobPrepared, OWNER_PAYLOAD)
			.expect("sync preceding frame before fault");
		owner_head.set(owner.head());
		let result = journal.append(FrameKind::PublishIntent, INTENT_PAYLOAD);
		assert!(matches!(
			result,
			Err(DurableJournalError::Sync(source)) if source.raw_os_error() == Some(errno)
		));
		let preserved = scratch.bytes();
		assert!(matches!(
			journal.append(FrameKind::PublishIntent, INTENT_PAYLOAD),
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
	let segment = TestSegment::with_barrier(readonly, |_| {
		panic!("failed write must stop before the barrier");
	});
	let mut journal = DurableJournal::from_new_segment(segment).expect("inspect empty fixture");
	assert!(matches!(
		journal.append(FrameKind::JobPrepared, OWNER_PAYLOAD),
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
	let barriers = Cell::new(0);
	let segment = TestSegment::with_barrier(file, |file| {
		barriers.set(barriers.get() + 1);
		file.sync_all()
	});
	let mut journal =
		DurableJournal::from_new_segment(segment).expect("admit exclusive empty file");
	let oversized = vec![0; MAX_PAYLOAD_BYTES + 1];
	assert!(matches!(
		journal.append(FrameKind::JobPrepared, &oversized),
		Err(DurableJournalError::Frame(
			FrameWriteError::PayloadTooLarge(_)
		))
	));
	assert!(scratch.bytes().is_empty(), "invalid input reached the file");
	assert_eq!(barriers.get(), 0);
	let synced = journal
		.append(FrameKind::JobPrepared, OWNER_PAYLOAD)
		.expect("valid append after an input rejection");
	assert_eq!(synced.head().sequence(), 1);
	assert_eq!(barriers.get(), 1);
}

#[test]
fn rejecting_a_frame_past_the_segment_limit_preserves_space_for_a_smaller_frame() {
	let (scratch, mut file) = ScratchFile::create();
	let limit = MAX_FIRST_SEGMENT_BYTES;
	let end = limit - u64::try_from(FRAME_OVERHEAD_BYTES).expect("frame overhead fits in u64");
	file.set_len(end).expect("make a sparse prefix fixture");
	file.seek(SeekFrom::Start(end))
		.expect("seek to the prefix end");
	let barriers = Cell::new(0);
	let segment = TestSegment::with_barrier(file, |file| {
		barriers.set(barriers.get() + 1);
		file.sync_all()
	});
	let mut journal = DurableJournal {
		writer: Some(FrameWriter::new(segment, ChainHead::start())),
		end,
	};
	assert!(matches!(
		journal.append(FrameKind::PublishIntent, b"x"),
		Err(DurableJournalError::SegmentTooLarge { length, limit: maximum })
			if length == limit + 1 && maximum == limit
	));
	assert_eq!(barriers.get(), 0);
	let mut read = File::open(&scratch.0).expect("open an independent reader");
	assert_eq!(
		read.metadata().expect("inspect unaffected extent").len(),
		end
	);
	let last = journal
		.append(FrameKind::PublishIntent, b"")
		.expect("a smaller frame fits exactly at the limit");
	assert_eq!(read.metadata().expect("inspect full extent").len(), limit);
	assert_eq!(barriers.get(), 1);
	read.seek(SeekFrom::Start(end))
		.expect("seek to the fixture frame");
	let mut reader = FrameReader::new(read, ChainHead::start());
	let frame = reader
		.next_frame()
		.expect("read fixture frame")
		.expect("fixture frame");
	assert_eq!(frame.head(), last.head());
	assert_eq!(reader.next_frame().expect("check end of fixture"), None);
}

#[test]
fn admission_rejects_nonempty_files_without_changing_them() {
	let (scratch, mut file) = ScratchFile::create();
	file.write_all(b"existing").expect("seed incumbent bytes");
	file.rewind().expect("return the cursor to the start");
	assert!(matches!(
		DurableJournal::from_new_segment(TestSegment::held(file)),
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
		DurableJournal::from_new_segment(TestSegment::held(file)),
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
		DurableJournal::from_new_segment(TestSegment::held(file)),
		Err(DurableJournalError::NotRegularFile)
	));
}

#[test]
fn changed_boundary_before_append_retires_the_writer() {
	let (scratch, file) = ScratchFile::create();
	let alias = file
		.try_clone()
		.expect("create a fixture-only duplicate writer");
	let mut journal = DurableJournal::from_new_segment(TestSegment::held(file))
		.expect("admit initially empty file");
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

fn synced_owner() -> (ScratchFile, ChainHead, u64) {
	let (scratch, file) = ScratchFile::create();
	let mut journal = DurableJournal::from_new_segment(TestSegment::held(file))
		.expect("admit exclusive empty file");
	let head = journal
		.append(FrameKind::JobPrepared, OWNER_PAYLOAD)
		.expect("sync the fixture owner frame")
		.head();
	let end = fs::metadata(&scratch.0)
		.expect("inspect fixture length")
		.len();
	(scratch, head, end)
}
