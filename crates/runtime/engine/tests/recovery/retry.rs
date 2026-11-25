use std::os::unix::fs::MetadataExt as _;

use exacopy_engine::linux::{RecoveryRetryError, RecoverySource, retry_recovery};

use super::*;

#[test]
fn retained_retry_uses_the_original_stage_inode_and_a_new_publication_effect() {
	let fixture = CopyFixture::new();
	retain_stage(&fixture);
	let original = fs::metadata(fixture.stage()).unwrap();
	let before = fs::read(fixture.job().join(JOURNAL_FILE)).unwrap();
	let outcome = retry(&fixture, 7).unwrap();
	assert_eq!(outcome.disposition, RecoveryDisposition::Complete);
	assert_eq!(
		fs::metadata(fixture.target()).unwrap().ino(),
		original.ino()
	);
	assert_eq!(fs::read(fixture.target()).unwrap(), DATA);
	assert_eq!(fs::read(fixture.path.join("source")).unwrap(), DATA);
	assert_absent(&fixture.stage());

	let journal = fs::read(fixture.job().join(JOURNAL_FILE)).unwrap();
	assert!(journal.starts_with(&before));
	let mut reader = FrameReader::new(&journal[before.len()..], initial_head(&before));
	let suffix = [
		FrameKind::RecoveryStarted,
		FrameKind::VerificationRecorded,
		FrameKind::MetadataRecorded,
		FrameKind::RecoveryDecision,
		FrameKind::PublishIntent,
		FrameKind::PublishObserved,
		FrameKind::RecoveryStarted,
		FrameKind::RecoveryDecision,
		FrameKind::DurabilityRecorded,
		FrameKind::ReceiptCommitted,
	];
	for kind in suffix {
		let frame = reader.next_frame().unwrap().unwrap();
		assert_eq!(frame.kind(), kind);
		if kind == FrameKind::PublishIntent {
			let intent = exacopy_journal::PublishIntent::from_frame(&frame).unwrap();
			assert_eq!(intent.context.effect_sequence, 2);
			assert_eq!(intent.context.epoch.get(), 3);
		}
	}
	assert!(reader.next_frame().unwrap().is_none());
	assert_eq!(retry(&fixture, 7).unwrap(), outcome);
	assert_eq!(fs::read(fixture.job().join(JOURNAL_FILE)).unwrap(), journal);
}

#[test]
fn changed_source_and_wrong_grant_preserve_a_retained_stage_and_prefix() {
	for changed in [false, true] {
		let fixture = CopyFixture::new();
		retain_stage(&fixture);
		let journal = fixture.job().join(JOURNAL_FILE);
		let before = fs::read(&journal).unwrap();
		if changed {
			fs::write(fixture.path.join("source"), vec![0; DATA.len()]).unwrap();
		}
		assert!(matches!(
			retry(&fixture, if changed { 7 } else { 99 }),
			Err(RecoveryRetryError::SourceMismatch)
		));
		assert_eq!(fs::read(journal).unwrap(), before);
		assert_eq!(fs::read(fixture.stage()).unwrap(), DATA);
		assert_absent(&fixture.target());
	}
}

#[test]
fn retained_retry_refuses_original_stage_access_time_drift() {
	let fixture = CopyFixture::new();
	retain_stage(&fixture);
	let stage = File::open(fixture.stage()).unwrap();
	stage
		.set_times(std::fs::FileTimes::new().set_accessed(std::time::SystemTime::UNIX_EPOCH))
		.unwrap();
	let path = fixture.job().join(JOURNAL_FILE);
	let before = fs::read(&path).unwrap();
	assert!(matches!(
		retry(&fixture, 7),
		Err(RecoveryRetryError::Stage(RecoveryIssue::MetadataMismatch))
	));
	assert_eq!(fs::read(path).unwrap(), before);
	assert_eq!(fs::read(fixture.stage()).unwrap(), DATA);
	assert_absent(&fixture.target());
}

fn retain_stage(fixture: &CopyFixture) {
	fixture.restore_stage();
	fixture.cut_after(FrameKind::PublishIntent, 0);
	fs::remove_file(fixture.job().join(RECEIPT_FILE)).unwrap();
	assert_eq!(fixture.disposition(), RecoveryDisposition::PossibleRetry);
}

fn retry(fixture: &CopyFixture, marker: u8) -> Result<RecoveryInspection, RecoveryRetryError> {
	let root = ReadRoot::from_directory(File::open(&fixture.path).unwrap()).unwrap();
	let id =
		RootCapabilityId::from_bytes([0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, marker])
			.unwrap();
	retry_recovery(
		&fixture.root,
		component(JOB),
		RecoveryProfile {
			id: fixture.profile,
			verifying_key: &fixture.key.verifying_key(),
		},
		RecoverySource { root: &root, id },
		&mut [0; 11],
	)
}

fn initial_head(prefix: &[u8]) -> ChainHead {
	let mut reader = FrameReader::new(prefix, ChainHead::start());
	let mut head = ChainHead::start();
	while let Some(frame) = reader.next_frame().unwrap() {
		head = frame.head();
	}
	head
}
