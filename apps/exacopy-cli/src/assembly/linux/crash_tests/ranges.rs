use std::fs::{self, File};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};

use exacopy_content::{ContentDigest, measure_at};
use exacopy_journal::frame::FrameKind;
use exacopy_journal::{MAX_CHECKPOINT_RANGE_BYTES, RangeCheckpoint, RangePage};

use super::evidence::{STAGE_DIRECTORY, read_frames};
use super::{
	Checkpoint, Fixture, JOB, RANGE_CHECKPOINTS, STAGE_FILE, TARGET, component, fixture_signer,
	open_destination, profile_id, run_copy_worker,
};
use crate::assembly::linux::{RecoveryDisposition, RecoveryProfile, inspect_recovery};

#[test]
fn kill_after_range_page_sync_before_frame() {
	kill_with_range(Checkpoint::RangePageSynced);
}

#[test]
fn kill_after_range_frame_sync() {
	kill_with_range(Checkpoint::RangeFrameSynced);
}

#[test]
#[ignore = "subprocess entrypoint for the native range checkpoint crash tests"]
fn range_worker() {
	RANGE_CHECKPOINTS.set(true);
	let result = run_copy_worker(&mut vec![0; 1024 * 1024]);
	panic!("worker unexpectedly survived range checkpoint: {result:?}");
}

fn kill_with_range(stop: Checkpoint) {
	let fixture = Fixture::new();
	let source = File::options()
		.read(true)
		.write(true)
		.open(fixture.source())
		.expect("open source fixture to set the test extent");
	source
		.set_len(MAX_CHECKPOINT_RANGE_BYTES + 1)
		.expect("extend the fixture past the checkpoint threshold");
	let before = source.metadata().expect("observe source before crash");
	let source_digest = digest(&source, before.len());
	drop(source);

	let (mut worker, _stream) = fixture.pause_worker(stop);
	worker.kill_at(stop);
	let mut order = vec![FrameKind::JobPrepared, FrameKind::EntryPrepared];
	if stop == Checkpoint::RangeFrameSynced {
		order.push(FrameKind::RangeCheckpoint);
	}
	let frames = read_frames(&fixture, &order);
	let page_path = fixture.job().join("checkpoints/range-0000000001.cbor");
	let bytes = fs::read(page_path).expect("retain the synchronized range page");
	let page = RangePage::decode(&bytes).expect("decode the retained range evidence");
	assert_eq!((page.ordinal(), page.offset()), (1, 0));
	if let Some(frame) = frames.get(2) {
		let checkpoint = RangeCheckpoint::from_frame(frame).expect("decode synchronized frame");
		assert_eq!(checkpoint.page, page.reference());
		assert_eq!(checkpoint.source, page.source());
	}
	let source = File::open(fixture.source()).expect("reopen source after crash");
	let after = source.metadata().expect("observe source after crash");
	assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
	assert_eq!(after.len(), before.len());
	assert_eq!(after.ctime(), before.ctime());
	assert_eq!(after.ctime_nsec(), before.ctime_nsec());
	assert_eq!(digest(&source, after.len()), source_digest);
	assert_eq!(
		digest(&source, page.length()).as_bytes(),
		page.digest().as_bytes()
	);

	let stage = File::open(fixture.job().join(STAGE_DIRECTORY).join(STAGE_FILE))
		.expect("reopen the retained stage");
	assert_eq!(
		stage.metadata().expect("stat the retained stage").len(),
		page.length()
	);
	assert_eq!(
		digest(&stage, page.length()).as_bytes(),
		page.digest().as_bytes()
	);
	assert_eq!(
		fixture
			.destination()
			.join(TARGET)
			.symlink_metadata()
			.expect_err("publication must not have begun")
			.kind(),
		std::io::ErrorKind::NotFound
	);
	let destination = open_destination(&fixture.destination());
	let inspection = inspect_recovery(
		&destination,
		component(JOB),
		RecoveryProfile {
			id: profile_id(),
			verifying_key: &fixture_signer().verifying_key(),
		},
		&mut [0; 4 * 1024],
	)
	.expect("inspect and preserve the interrupted copy");
	assert_eq!(
		inspection.journal.head,
		frames.last().expect("recorded prefix").head()
	);
	assert_eq!(
		inspection.disposition,
		RecoveryDisposition::RetainedPreparation
	);
}

fn digest(file: &File, length: u64) -> ContentDigest {
	measure_at(length, &mut [0; 64 * 1024], |offset, bytes| {
		file.read_exact_at(bytes, offset)
	})
	.expect("measure the complete fixture range")
}
