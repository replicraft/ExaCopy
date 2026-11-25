use std::os::unix::fs::MetadataExt as _;

use exacopy_transfer::linux::finish_recovery;

use super::{
	CopyFixture, DATA, FrameKind, JOB, JOURNAL_FILE, JournalTail, RECEIPT_FILE,
	RecoveryDisposition, RecoveryProfile, assert_absent, component, fs,
};

#[test]
fn finishes_an_observed_rename_then_repeats_without_changing_evidence() {
	let fixture = CopyFixture::new();
	let original = fs::metadata(fixture.target()).expect("initial published inode");
	fixture.cut_after(FrameKind::PublishIntent, 0);
	fs::remove_file(fixture.job().join(RECEIPT_FILE)).expect("reconstruct interrupted receipt");
	assert_eq!(
		fixture.disposition(),
		RecoveryDisposition::PublishedNeedsBarriers
	);

	let completed = finish(&fixture);
	assert_eq!(completed.disposition, RecoveryDisposition::Complete);
	assert_eq!(completed.journal.head.sequence(), 11);
	assert_eq!(fixture.disposition(), RecoveryDisposition::Complete);
	assert_eq!(
		fs::metadata(fixture.target()).unwrap().ino(),
		original.ino()
	);
	assert_eq!(fs::read(fixture.target()).unwrap(), DATA);
	assert_eq!(fs::read(fixture.path.join("source")).unwrap(), DATA);
	assert_absent(&fixture.stage());

	let journal_path = fixture.job().join(JOURNAL_FILE);
	let bytes = fs::read(&journal_path).expect("snapshot completed journal");
	assert_eq!(finish(&fixture), completed);
	assert_eq!(fs::read(journal_path).unwrap(), bytes);
}

#[test]
fn keeps_the_original_receipt_inode_and_handles_an_interrupted_recovery_start() {
	let fixture = CopyFixture::new();
	fixture.cut_after(FrameKind::DurabilityRecorded, 0);
	let receipt_path = fixture.job().join(RECEIPT_FILE);
	let bytes = fs::read(&receipt_path).expect("existing valid receipt");
	let inode = fs::metadata(&receipt_path)
		.expect("existing receipt inode")
		.ino();
	assert_eq!(finish(&fixture).disposition, RecoveryDisposition::Complete);

	fixture.cut_after(FrameKind::RecoveryStarted, 0);
	assert_eq!(
		fixture.disposition(),
		RecoveryDisposition::PublishedNeedsReceipt {
			artifact_present: true
		}
	);
	let resumed = finish(&fixture);
	assert_eq!(resumed.disposition, RecoveryDisposition::Complete);
	assert_eq!(resumed.journal.head.sequence(), 12);
	assert_eq!(fs::metadata(&receipt_path).unwrap().ino(), inode);
	assert_eq!(fs::read(receipt_path).unwrap(), bytes);
}

#[test]
fn retains_stage_only_and_torn_prefixes_without_writing_records() {
	let fixture = CopyFixture::new();
	fixture.restore_stage();
	fixture.cut_after(FrameKind::PublishIntent, 0);
	fs::remove_file(fixture.job().join(RECEIPT_FILE)).expect("remove later fixture receipt");
	let journal_path = fixture.job().join(JOURNAL_FILE);
	let bytes = fs::read(&journal_path).unwrap();
	assert_eq!(
		finish(&fixture).disposition,
		RecoveryDisposition::PossibleRetry
	);
	assert_eq!(fs::read(&journal_path).unwrap(), bytes);
	assert_absent(&fixture.target());
	assert_eq!(fs::read(fixture.stage()).unwrap(), DATA);

	let fixture = CopyFixture::new();
	fixture.cut_after(FrameKind::PublishIntent, 1);
	fs::remove_file(fixture.job().join(RECEIPT_FILE)).expect("remove later fixture receipt");
	let journal_path = fixture.job().join(JOURNAL_FILE);
	let bytes = fs::read(&journal_path).unwrap();
	assert_eq!(finish(&fixture).tail, JournalTail::Torn { bytes_read: 1 });
	assert_eq!(fs::read(journal_path).unwrap(), bytes);
	assert_eq!(fs::read(fixture.target()).unwrap(), DATA);
}

fn finish(fixture: &CopyFixture) -> super::RecoveryInspection {
	finish_recovery(
		&fixture.root,
		component(JOB),
		RecoveryProfile {
			id: fixture.profile,
			verifying_key: &fixture.key.verifying_key(),
		},
		&mut [0; 11],
	)
	.expect("finish an authenticated fixture copy")
}
