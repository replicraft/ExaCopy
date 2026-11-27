use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};

use exacopy_endpoint::{JournalFileBarrier, JournalSegment, UnixComponent};

use super::LinuxJournalSegment;
use crate::linux::DestinationRoot;
use crate::linux::job::{FIRST_SEGMENT, JOURNAL};
use crate::scratch::Scratch;

const JOB: &str = "fixture-segment-job";
const PREFIX: &[u8] = b"first bytes";
const SUFFIX: &[u8] = b"more bytes";

#[test]
fn fresh_journal_segment_preserves_bytes_and_shares_one_cursor() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).expect("held destination root");
	let name = UnixComponent::new(JOB.as_bytes()).expect("valid job component");
	let mut segment = {
		let job = root.create_job_directory(name).expect("create private job");
		let journal = job
			.create_journal_directory()
			.expect("create private journal");
		journal.create_first_segment().expect("admit new segment")
	};
	scratch.assert_debug_redacts(&segment, &[JOB, JOURNAL, FIRST_SEGMENT]);
	assert_eq!(LinuxJournalSegment::BARRIER, JournalFileBarrier::SyncAll);
	assert_eq!(
		segment.regular_length().expect("inspect empty segment"),
		Some(0)
	);

	segment.write_all(PREFIX).expect("write the segment prefix");
	segment.flush().expect("flush the segment writer");
	assert_eq!(
		segment.regular_length().expect("observe the first write"),
		Some(u64::try_from(PREFIX.len()).expect("fixture prefix fits a file length"))
	);

	segment.rewind().expect("rewind the same segment");
	let negative_seek = segment
		.seek(SeekFrom::Current(-1))
		.expect_err("a cursor cannot move before the start");
	assert_eq!(negative_seek.kind(), ErrorKind::InvalidInput);

	let mut prefix = [0; PREFIX.len()];
	segment
		.read_exact(&mut prefix)
		.expect("read the prefix from the unchanged cursor");
	assert_eq!(prefix.as_slice(), PREFIX);
	let mut next_byte = [0];
	assert_eq!(segment.read(&mut next_byte).expect("read at end"), 0);

	segment
		.rewind()
		.expect("rewind for an interior cursor observation");
	segment
		.read_exact(&mut next_byte)
		.expect("advance reader by one byte");
	assert_eq!(&next_byte, b"f");
	segment
		.write_all(b"Z")
		.expect("overwrite at the reader cursor");
	assert_eq!(
		segment
			.regular_length()
			.expect("interior write preserves extent"),
		Some(PREFIX.len() as u64)
	);
	assert_eq!(
		std::fs::read(scratch.path(JOB).join(JOURNAL).join(FIRST_SEGMENT))
			.expect("independently read interior overwrite"),
		b"fZrst bytes"
	);
	segment
		.seek(SeekFrom::End(0))
		.expect("select current EOF for suffix");

	segment
		.write_all(SUFFIX)
		.expect("extend the segment from the shared cursor");
	segment.sync().expect("run the declared file barrier");
	assert_eq!(
		segment.regular_length().expect("observe the extension"),
		Some(u64::try_from(PREFIX.len() + SUFFIX.len()).expect("fixture fits a file length"))
	);

	segment.rewind().expect("rewind for final read-back");
	let mut contents = [0; PREFIX.len() + SUFFIX.len()];
	segment
		.read_exact(&mut contents)
		.expect("read back the complete segment");
	assert_eq!(&contents[..PREFIX.len()], b"fZrst bytes");
	assert_eq!(&contents[PREFIX.len()..], SUFFIX);
}
