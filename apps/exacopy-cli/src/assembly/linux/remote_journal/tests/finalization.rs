use std::num::NonZeroU64;

use exacopy_endpoint::JournalFileBarrier;
use exacopy_endpoint::linux_publication::{ReceiptDirectory, ReceiptWorkspace};
use exacopy_journal::StreamLength;
use exacopy_journal::frame::{ChainHead, FrameKind};
use exacopy_journal::remote_download::finalization::{
	RemoteFinalizationBinding, RemoteFinalizationBody, RemoteFinalizationRecord,
};
use exacopy_transfer::remote_finalization::{RemoteFinalizationJournal, RemoteReceiptWorkspace};

use super::{Fixture, LENGTH, NONCE, STAGE, component, observation};
use crate::assembly::linux::remote_journal::{Error, IntentReadback, record_identity};

#[test]
fn native_adapter_admits_only_the_actual_active_predecessor_and_readback() {
	let fixture = Fixture::new();
	let lease = fixture.open_bootstrap(fixture.bootstrap());
	let candidate = lease.candidate(component(STAGE).unwrap()).unwrap();
	let mut journal = lease.open_writer(&candidate).unwrap();
	let mut allocation = journal
		.allocate(&candidate, NonZeroU64::MIN, observation(), NONCE)
		.unwrap();
	let mut bound = allocation.create(&mut journal).unwrap();
	bound.writer.write_all_at(0, b"remote stream").unwrap();
	bound.writer.sync_prefix(LENGTH).unwrap();
	let closed = bound.writer.close_writes().unwrap();
	let snapshot = lease.finalization_history(&journal).unwrap();
	let attempt = &snapshot.replay.attempts()[0];
	let expected = snapshot.replay.boundary();
	let identity = record_identity(closed.identity());
	let context = lease.context();
	let record = RemoteFinalizationRecord::new(
		RemoteFinalizationBinding {
			context,
			prepared: snapshot.prepared.head(),
			epochs: attempt.epochs(),
			stage: identity,
		},
		expected.head,
		RemoteFinalizationBody::StageSealed {
			directory: record_identity(bound.directory),
			length: StreamLength::new(LENGTH).unwrap(),
		},
	)
	.unwrap();
	let intent = IntentReadback::default();
	let mut app = journal.finalization(&intent).unwrap();
	let stale = ChainHead::after(expected.head.sequence(), [0x35; 32]).unwrap();
	let mut changed = expected;
	changed.head = stale;
	assert!(matches!(
		app.append(changed, FrameKind::StageSealed, record.encode().unwrap()),
		Err(Error::Binding)
	));
	assert_eq!(app.boundary().unwrap(), expected);
	let (frame, synced) = app
		.append(expected, FrameKind::StageSealed, record.encode().unwrap())
		.unwrap();
	assert_eq!(frame.head(), synced.head());
	assert_eq!(synced.barrier(), JournalFileBarrier::SyncAll);
	assert_eq!(
		RemoteFinalizationRecord::from_frame(&frame).unwrap(),
		record
	);
	assert_eq!(app.boundary().unwrap().head, frame.head());
	assert!(!fixture.target().exists());
}

#[test]
fn receipt_workspace_checks_job_and_creates_only_one_exclusive_directory_and_file() {
	let fixture = Fixture::new();
	let lease = fixture.open_bootstrap(fixture.bootstrap());
	let receipts = lease.receipts();
	let expected = record_identity(lease.job().identity());
	assert!(
		receipts
			.check_job(exacopy_journal::LinuxFileIdentity::new(1, 2))
			.is_err()
	);
	receipts.check_job(expected).unwrap();
	let directory = receipts.create_receipt_directory().unwrap();
	assert!(receipts.create_receipt_directory().is_err());
	let record = directory.create_receipt_record().unwrap();
	assert!(directory.create_receipt_record().is_err());
	drop(record);
	directory.sync_directory().unwrap();
	receipts.sync_directory().unwrap();
}
