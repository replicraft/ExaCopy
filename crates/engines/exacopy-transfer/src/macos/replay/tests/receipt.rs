use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;

use exacopy_journal::frame::FrameKind;
use exacopy_journal::{
	DarwinReceiptCommitted, DarwinReceiptDigest, DurableJournal, JournalFileBarrier,
};

use super::Fixture;
use crate::macos::receipt::{DarwinCopyReceipt, DarwinReceiptFrames};
use crate::macos::replay::{DarwinReplayError, DarwinReplayStatus};

#[test]
fn validates_canonical_receipt_and_independent_digest_against_the_accepted_chain() {
	let fixture = Fixture::new();
	let mut history = fixture.records.prefix(8);
	let frames = &history.frames;
	let durability = &frames[7];
	let synced = {
		let path = std::env::temp_dir().join(format!(
			"exacopy-apfs-replay-{}.journal",
			std::process::id()
		));
		let mut file = OpenOptions::new()
			.create_new(true)
			.read(true)
			.write(true)
			.open(&path)
			.unwrap();
		let _owned_test_file = TestFile(path);
		let prefix_end = history.ends[6];
		file.write_all(&history.bytes[..prefix_end]).unwrap();
		let mut journal = DurableJournal::resume_first_segment_with_barrier(
			file,
			frames[6].head(),
			prefix_end as u64,
			JournalFileBarrier::DarwinFullFsync,
		)
		.unwrap();
		journal
			.append(durability.kind(), durability.payload())
			.unwrap()
	};
	let receipt = DarwinCopyReceipt::from_synced_durability(
		&fixture.plan,
		DarwinReceiptFrames {
			verification: &frames[3],
			metadata: &frames[4],
			intent: &frames[5],
			observed: &frames[6],
			durability,
		},
		&synced,
	)
	.unwrap();
	let bytes = receipt.encode();
	assert!(matches!(
		fixture
			.replay(&history.bytes)
			.unwrap()
			.validate_receipt(&fixture.plan, &bytes),
		Err(DarwinReplayError::MissingReceiptCommitment),
	));

	let committed = DarwinReceiptCommitted::new(durability, receipt.digest()).unwrap();
	let wrong_digest =
		DarwinReceiptCommitted::new(durability, DarwinReceiptDigest::from_bytes([10; 32])).unwrap();
	history.append(FrameKind::ReceiptCommitted, &committed.encode());
	let replay = fixture.replay(&history.bytes).unwrap();
	assert_eq!(replay.status(), DarwinReplayStatus::Complete);
	assert_eq!(
		replay.validate_receipt(&fixture.plan, &bytes).unwrap(),
		receipt
	);
	let mut damaged = bytes.clone();
	damaged.push(0);
	assert!(matches!(
		replay.validate_receipt(&fixture.plan, &damaged),
		Err(DarwinReplayError::Receipt(_))
	));

	let mut history = fixture.records.prefix(8);
	history.append(FrameKind::ReceiptCommitted, &wrong_digest.encode());
	let replay = fixture.replay(&history.bytes).unwrap();
	assert_eq!(replay.status(), DarwinReplayStatus::Complete);
	assert!(matches!(
		replay.validate_receipt(&fixture.plan, &bytes),
		Err(DarwinReplayError::Phase(_))
	));
}

struct TestFile(PathBuf);

impl Drop for TestFile {
	fn drop(&mut self) {
		let _ = fs::remove_file(&self.0);
	}
}
