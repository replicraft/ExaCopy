use std::fs::{self, File};
use std::io::Read as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use exacopy_journal::frame::{ChainHead, Frame, FrameKind, FrameReader};
use exacopy_journal::{
	LOCAL_RECEIPT_LOCATION, MAX_CHECKPOINT_RANGE_BYTES, RangeCheckpoint, RangePage,
	RangeResumeStarted, ReceiptCommitted,
};
use exacopy_transfer::linux::CopyReceipt;
use serde_json::Value;

use super::{Fixture, PROFILE, job_directory, json};

const SOURCE_ROOT: &str = "source-root";
const SOURCE: &str = "source-root/source";
const TARGET: &str = "target";
const SEGMENT: &str = "journal/00000000000000000001.exajnl";
const SUFFIX: &[u8] = b"range after the checkpoint";

#[test]
fn resumes_a_checkpointed_copy_and_repeats_with_the_same_receipt() {
	let fixture = Fixture::with_profile();
	fs::create_dir(fixture.path(SOURCE_ROOT)).expect("create original source root");
	let source = fixture.path(SOURCE);
	let file = File::options()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(&source)
		.expect("create a private synthetic source");
	file.write_all_at(b"measured prefix", 0)
		.expect("seed checkpoint bytes");
	file.write_all_at(SUFFIX, MAX_CHECKPOINT_RANGE_BYTES)
		.expect("seed the uncheckpointed suffix");
	let source_inode = file.metadata().expect("observe source inode").ino();
	drop(file);
	let source_digest = digest(&source);

	let copied = json(
		fixture.copy(SOURCE, TARGET).output().expect("invoke copy"),
		0,
	);
	let job = job_directory(&fixture, &copied);
	let stage = job.join("stage/data");
	let journal = job.join(SEGMENT);
	let receipt = job.join(LOCAL_RECEIPT_LOCATION);
	let target = fixture.path(TARGET);

	let mut reader = FrameReader::new(File::open(&journal).unwrap(), ChainHead::start());
	next_frame(&mut reader, FrameKind::JobPrepared);
	next_frame(&mut reader, FrameKind::EntryPrepared);
	let checkpoint =
		RangeCheckpoint::from_frame(&next_frame(&mut reader, FrameKind::RangeCheckpoint))
			.expect("decode referenced range");
	let checkpoint_head = reader.head();
	let checkpoint_offset = reader.offset();
	let page_path = job.join(format!(
		"checkpoints/range-{:010}.cbor",
		checkpoint.page.ordinal()
	));
	let page_bytes = fs::read(&page_path).expect("read checkpoint page");
	let page = RangePage::decode(&page_bytes).expect("decode checkpoint page");
	assert_eq!(page.reference(), checkpoint.page);
	assert_eq!(page.offset(), 0);
	// The time threshold can close the first range before its byte limit.
	assert!((1..=MAX_CHECKPOINT_RANGE_BYTES).contains(&page.length()));

	// Reconstruct the private inode and journal at the first persisted checkpoint.
	// Keep the authenticated plan, owner envelope and checkpoint page from the copy.
	fs::rename(&target, &stage).expect("restore private stage in disposable fixture");
	let stage_file = File::options().write(true).open(&stage).unwrap();
	stage_file.set_len(page.length()).expect("keep first range");
	let stage_inode = stage_file.metadata().expect("observe retained inode").ino();
	drop(stage_file);
	File::options()
		.write(true)
		.open(&journal)
		.unwrap()
		.set_len(checkpoint_offset)
		.expect("keep journal through the first range checkpoint");
	fs::remove_file(&receipt).expect("remove later receipt from disposable fixture");
	let prefix = fs::read(&journal).expect("save accepted journal prefix");

	let completed = resume(&fixture, &job);
	assert_eq!(completed["disposition"], "complete");
	assert_eq!(completed["journal_tail"], "clean");
	assert_eq!(fs::metadata(&target).unwrap().ino(), stage_inode);
	assert!(!stage.exists());

	let committed_journal = fs::read(&journal).expect("read completed journal");
	assert!(committed_journal.starts_with(&prefix));
	assert_eq!(fs::read(&page_path).unwrap(), page_bytes);
	let receipt_bytes = fs::read(&receipt).expect("read resumed receipt");
	let artifact = CopyReceipt::decode(&receipt_bytes).expect("decode resumed receipt");
	assert_eq!(artifact.evidence().stream.identity.inode(), stage_inode);
	assert_eq!(
		artifact.evidence().stream.digest.as_bytes(),
		source_digest.as_bytes()
	);

	let mut reader = FrameReader::new(committed_journal.as_slice(), ChainHead::start());
	for kind in [
		FrameKind::JobPrepared,
		FrameKind::EntryPrepared,
		FrameKind::RangeCheckpoint,
	] {
		next_frame(&mut reader, kind);
	}
	assert_eq!(reader.head(), checkpoint_head);
	let resumed =
		RangeResumeStarted::from_frame(&next_frame(&mut reader, FrameKind::RecoveryStarted))
			.expect("decode the pre-intent resume start");
	assert_eq!(resumed.evidence().preceding, checkpoint_head);
	assert_eq!(resumed.prior_epoch(), checkpoint.context.epoch);
	assert_eq!(resumed.context(), artifact.evidence().context);

	for kind in [
		FrameKind::StageSealed,
		FrameKind::VerificationRecorded,
		FrameKind::MetadataRecorded,
		FrameKind::PublishIntent,
		FrameKind::PublishObserved,
		FrameKind::DurabilityRecorded,
	] {
		next_frame(&mut reader, kind);
	}
	assert_eq!(reader.head(), artifact.durability_frame());
	let commitment = next_frame(&mut reader, FrameKind::ReceiptCommitted);
	let committed = ReceiptCommitted::decode(commitment.payload()).expect("decode commitment");
	assert_eq!(committed.digest().as_bytes(), &artifact.digest());
	assert_eq!(committed.durability(), artifact.durability_frame());
	assert_eq!(
		completed["journal_sequence"],
		reader.head().sequence().to_string()
	);
	assert_eq!(completed["journal_offset"], reader.offset().to_string());
	assert!(reader.next_frame().expect("read journal EOF").is_none());

	assert_eq!(resume(&fixture, &job), completed);
	assert_eq!(fs::read(&journal).unwrap(), committed_journal);
	assert_eq!(fs::read(&receipt).unwrap(), receipt_bytes);
	assert_eq!(fs::metadata(&source).unwrap().ino(), source_inode);
	assert_eq!(digest(&source), source_digest);
	assert_eq!(digest(&target), source_digest);
}

fn next_frame(reader: &mut FrameReader<impl std::io::Read>, kind: FrameKind) -> Frame {
	let frame = reader
		.next_frame()
		.expect("read validated journal frame")
		.expect("journal frame exists");
	assert_eq!(frame.kind(), kind);
	frame
}

fn digest(path: &Path) -> blake3::Hash {
	let mut file = File::open(path).expect("open fixture file for hashing");
	let mut hasher = blake3::Hasher::new();
	let mut scratch = [0; 8192];
	loop {
		let length = file.read(&mut scratch).expect("read fixture stream");
		if length == 0 {
			return hasher.finalize();
		}
		hasher.update(&scratch[..length]);
	}
}

fn resume(fixture: &Fixture, job: &Path) -> Value {
	let output = fixture
		.command()
		.args(["recover", "resume"])
		.arg(job)
		.args([
			"--source-root",
			SOURCE_ROOT,
			"--profile",
			PROFILE,
			"--format",
			"json",
		])
		.output()
		.expect("resume a partial copy");
	assert_eq!(output.status.code(), Some(0), "{output:?}");
	assert!(output.stderr.is_empty());
	let report: Value = serde_json::from_slice(&output.stdout).expect("decode recovery report");
	assert_eq!(report["schema"], "exacopy.local_recovery_inspection");
	assert_eq!(report["schema_version"], "1.0");
	report
}
