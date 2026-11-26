use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;

use exacopy_endpoint::FreshStage;
use exacopy_journal::StreamDigest;
use exacopy_journal::frame::{FrameKind, FrameWriter};
use exacopy_journal::remote_download::{RemoteDownloadBody, RemoteDownloadRecord};
use exacopy_transfer::remote_capture::CheckpointStage;

use crate::assembly::linux::remote_stage::{NativeCaptureStage, PrefixBarrier};

use super::{Error, Fixture, LENGTH, NONCE, RemoteJobLease, STAGE, component, epoch, observation};

const OLD_BYTES: &[u8; LENGTH as usize] = b"earlier bytes";
const FRESH: &[u8] = b"fresh-basename";

fn leave_old_stage(fixture: &Fixture, covered: usize, physical: usize) {
	let lease = fixture.open_bootstrap(fixture.bootstrap());
	let candidate = lease.candidate(component(STAGE).unwrap()).unwrap();
	let mut ledger = lease.open_writer(&candidate).unwrap();
	let mut allocation = ledger
		.allocate(&candidate, epoch(1), observation(), NONCE)
		.unwrap();
	let bound = allocation.create(&mut ledger).unwrap();
	let barrier = PrefixBarrier::new(bound.prefix_scope);
	let mut old = NativeCaptureStage::new(
		bound.writer,
		lease.job(),
		bound.name,
		bound.target,
		bound.directory,
		bound.length,
		&barrier,
	)
	.unwrap();
	if covered != 0 {
		let prefix = &OLD_BYTES[..covered];
		old.write_next(prefix).unwrap();
		old.sync_prefix(covered as u64).unwrap();
	}
	if physical > covered {
		old.write_next(&OLD_BYTES[covered..physical]).unwrap();
	}
	let context = lease.context();
	drop(old);
	drop(allocation);
	drop(ledger);
	drop(lease);

	// Model a canonical accepted prefix record. Its real file barrier above
	// ran at the prefix before the later, unacknowledged native write.
	if covered > 0 {
		let replay = fixture.replay();
		let attempt = &replay.attempts()[0];
		let record = RemoteDownloadRecord::new(
			context,
			Some(replay.boundary().head),
			RemoteDownloadBody::RangeCheckpoint {
				prepared: attempt.prepared().unwrap().head,
				epochs: attempt.epochs(),
				ordinal: 1,
				offset: 0,
				length: covered as u64,
				digest: StreamDigest::from_bytes(*blake3::hash(&OLD_BYTES[..covered]).as_bytes()),
			},
		)
		.unwrap();
		let file = OpenOptions::new()
			.append(true)
			.open(fixture.segment())
			.unwrap();
		let mut journal = FrameWriter::new(file, replay.boundary().head);
		let _ = journal
			.append(FrameKind::RangeCheckpoint, &record.encode().unwrap())
			.unwrap();
		journal.into_inner().sync_all().unwrap();
	}
	// Model process loss without acknowledging the remainder. No original
	// stage writer, segment writer, or lease handle reaches the new reader.
}

fn reopen(fixture: &Fixture) -> Result<RemoteJobLease<'_>, Error> {
	RemoteJobLease::open_existing(&fixture.profile, fixture.job, fixture.activation())
}

#[test]
fn a_new_reader_reconciles_bounded_unacknowledged_old_bytes_and_writes_at_zero_elsewhere() {
	for (covered, physical) in [(0, 0), (0, 1), (0, 13), (4, 4), (4, 8), (4, 13)] {
		let fixture = Fixture::new();
		leave_old_stage(&fixture, covered, physical);
		let replay = fixture.replay();
		assert_eq!(replay.attempts()[0].covered_extent(), covered as u64);
		assert!(replay.recorded_uncertainty().is_none());
		assert_eq!(
			fs::read(fixture.stage("capture-1")).unwrap(),
			&OLD_BYTES[..physical]
		);

		let lease = reopen(&fixture).unwrap();
		let candidate = lease.candidate(component(FRESH).unwrap()).unwrap();
		let mut ledger = lease.open_fresh_capture(&candidate).unwrap();
		let mut allocation = ledger
			.allocate(&candidate, epoch(2), observation(), [0x62; 16])
			.unwrap();
		let mut bound = allocation.create(&mut ledger).unwrap();
		assert_eq!(
			fs::metadata(fixture.stage("fresh-basename")).unwrap().len(),
			0
		);
		bound.writer.write_all_at(0, b"fresh").unwrap();
		assert_eq!(fs::read(fixture.stage("fresh-basename")).unwrap(), b"fresh");
		assert_eq!(
			fs::read(fixture.stage("capture-1")).unwrap(),
			&OLD_BYTES[..physical]
		);
		assert!(!fixture.target().exists());
	}
}

#[test]
fn recovery_refuses_a_physically_shorter_than_covered_or_overextent_old_stage() {
	for corrupt_extent in [3, LENGTH + 1] {
		let fixture = Fixture::new();
		leave_old_stage(&fixture, 4, 4);
		let old = fixture.stage("capture-1");
		OpenOptions::new()
			.write(true)
			.open(&old)
			.unwrap()
			.set_len(corrupt_extent)
			.unwrap();
		let journal = fs::read(fixture.segment()).unwrap();
		assert!(matches!(reopen(&fixture), Err(Error::UnknownStage)));
		assert_eq!(fs::read(fixture.segment()).unwrap(), journal);
		assert_eq!(fs::metadata(old).unwrap().len(), corrupt_extent);
		assert!(!fixture.stage("fresh-basename").exists());
	}
}

#[test]
fn a_preserved_inode_is_rechecked_between_allocation_and_fresh_creation() {
	let fixture = Fixture::new();
	leave_old_stage(&fixture, 4, 8);
	let lease = reopen(&fixture).unwrap();
	let candidate = lease.candidate(component(FRESH).unwrap()).unwrap();
	let mut ledger = lease.open_fresh_capture(&candidate).unwrap();
	let mut allocation = ledger
		.allocate(&candidate, epoch(2), observation(), [0x62; 16])
		.unwrap();
	let before = fs::read(fixture.segment()).unwrap();
	let old = fixture.stage("capture-1");
	fs::rename(&old, fixture.stage("renamed-by-fixture")).unwrap();
	OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&old)
		.unwrap()
		.write_all(&OLD_BYTES[..8])
		.unwrap();

	assert!(allocation.create(&mut ledger).is_err());
	assert_eq!(fs::read(fixture.segment()).unwrap(), before);
	assert!(!fixture.stage("fresh-basename").exists());
	assert_eq!(
		fs::read(fixture.stage("renamed-by-fixture")).unwrap(),
		&OLD_BYTES[..8]
	);
	assert!(!fixture.target().exists());
}
