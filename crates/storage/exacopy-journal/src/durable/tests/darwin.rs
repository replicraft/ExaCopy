//! Simulated barrier attribution and writer retirement, with no native syscall claim.

use std::io;

use super::fixture::SimulatedDarwinSegment;
use super::{INTENT_PAYLOAD, OWNER_PAYLOAD, ScratchFile};
use crate::frame::FrameKind;
use crate::{DurableJournal, DurableJournalError, JournalFileBarrier};

const BARRIER: JournalFileBarrier = JournalFileBarrier::DarwinFullFsync;

#[test]
fn simulated_full_fsync_records_can_resume_the_same_readable_chain() {
	let (scratch, file) = ScratchFile::create();
	let segment = SimulatedDarwinSegment::with_barrier(file, |_| Ok(()));
	let mut journal = DurableJournal::from_new_segment(segment)
		.expect("open a segment with a simulated Darwin barrier");
	let prepared = journal
		.append(FrameKind::JobPrepared, OWNER_PAYLOAD)
		.expect("full-sync the first frame");
	assert_eq!(prepared.barrier(), BARRIER);
	drop(journal);
	let prefix = scratch.bytes();

	let segment = SimulatedDarwinSegment::with_barrier(scratch.reopen(), |_| Ok(()));
	let mut journal =
		DurableJournal::resume_first_segment(segment, prepared.head(), prefix.len() as u64)
			.expect("validate and full-sync the original prefix");
	let intent = journal
		.append(FrameKind::PublishIntent, INTENT_PAYLOAD)
		.expect("full-sync the next frame");
	assert_eq!(intent.barrier(), BARRIER);
	assert!(scratch.bytes().starts_with(&prefix));

	let mut reader = scratch.reader();
	let first = reader.next_frame().unwrap().unwrap();
	let second = reader.next_frame().unwrap().unwrap();
	assert_eq!(first.head(), prepared.head());
	assert_eq!(second.previous_digest(), prepared.head().digest());
	assert_eq!(second.head(), intent.head());
	assert!(reader.next_frame().unwrap().is_none());
}

#[test]
fn simulated_full_fsync_failure_returns_no_evidence_and_retires_the_writer() {
	let (scratch, file) = ScratchFile::create();
	let segment = SimulatedDarwinSegment::with_barrier(file, |_| {
		let frame = scratch.reader().next_frame().unwrap().unwrap();
		assert_eq!(frame.payload(), INTENT_PAYLOAD);
		Err(io::Error::other("simulated full sync failure"))
	});
	let mut journal = DurableJournal::from_new_segment(segment)
		.expect("open a segment with an injected Darwin barrier failure");
	let result = journal.append(FrameKind::PublishIntent, INTENT_PAYLOAD);
	assert!(matches!(result, Err(DurableJournalError::Sync(_))));
	let retained = scratch.bytes();
	assert!(matches!(
		journal.append(FrameKind::PublishIntent, INTENT_PAYLOAD),
		Err(DurableJournalError::Retired)
	));
	assert_eq!(scratch.bytes(), retained);
}
