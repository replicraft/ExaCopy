use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use exacopy_engine::linux::{
	CopyRoots, RecoveryFinishError, copy_new_file, finish_recovery, plan_new_file,
};
use exacopy_journal::{JournalJobId, OwnerTimestamp, OwnerToken};
use exacopy_platform::linux::ReadRoot;
use exacopy_transfer::linux::{CopyProfile, CopyReceipt, LocalCopyPlan, PlanAttempt};

use super::{
	CopyFixture, DATA, File, FrameKind, JOB, JOURNAL_FILE, JournalTail, OWNER_FILE, OsStr,
	PLAN_FILE, RECEIPT_FILE, RecoveryDisposition, RecoveryInspectError, RecoveryInspection,
	RecoveryProfile, assert_absent, component, fs,
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

#[test]
fn rejects_a_canonical_receipt_from_another_job_under_the_same_trusted_profile() {
	let fixture = CopyFixture::new();
	let recipient_path = fixture.job().join(RECEIPT_FILE);
	let recipient_bytes = fs::read(&recipient_path).expect("read committed recipient receipt");
	let recipient = CopyReceipt::decode(&recipient_bytes).expect("decode recipient receipt");
	let donor_bytes = copy_donor(&fixture);
	let donor = CopyReceipt::decode(&donor_bytes).expect("decode donor receipt");
	let donor_evidence = donor.evidence();
	let recipient_evidence = recipient.evidence();
	assert_ne!(donor_evidence.context.job, recipient_evidence.context.job);
	assert_ne!(
		donor_evidence.context.plan_digest,
		recipient_evidence.context.plan_digest
	);
	assert_eq!(donor_evidence.source, recipient_evidence.source);
	assert_eq!(
		donor_evidence.stream.digest,
		recipient_evidence.stream.digest
	);
	assert_eq!(
		donor_evidence.stream.length,
		recipient_evidence.stream.length
	);

	fixture.cut_after(FrameKind::DurabilityRecorded, 0);
	assert_eq!(
		fixture.disposition(),
		RecoveryDisposition::PublishedNeedsReceipt {
			artifact_present: true
		}
	);
	assert_rejects_receipt_without_mutation(&fixture, &recipient_path, &donor_bytes);

	// Keep the foreign receipt body and match the recipient's durability frame to
	// exercise the evidence comparison independently of the journal reference.
	let foreign_anchor = donor.durability_frame().digest();
	let local_anchor = recipient.durability_frame().digest();
	let mut rebound = donor_bytes.clone();
	let anchor_offset = rebound
		.windows(foreign_anchor.len())
		.position(|bytes| bytes == foreign_anchor)
		.expect("locate donor durability digest in its canonical receipt");
	rebound[anchor_offset..anchor_offset + foreign_anchor.len()].copy_from_slice(&local_anchor);
	let decoded = CopyReceipt::decode(&rebound).expect("receipt still has canonical encoding");
	assert_eq!(decoded.durability_frame(), recipient.durability_frame());
	assert_eq!(decoded.evidence(), donor_evidence);
	assert_rejects_receipt_without_mutation(&fixture, &recipient_path, &rebound);
}

fn copy_donor(fixture: &CopyFixture) -> Vec<u8> {
	const DONOR_JOB: &[u8] = b"donor-job";
	const DONOR_TARGET: &[u8] = b"donor-target";

	let plan_bytes = fs::read(fixture.job().join(PLAN_FILE)).expect("read recipient plan");
	let plan = LocalCopyPlan::decode(&plan_bytes).expect("decode recipient plan");
	let source = ReadRoot::from_directory(File::open(&fixture.path).expect("open fixture source"))
		.expect("admit same fixture source");
	let roots = CopyRoots {
		source: &source,
		destination: &fixture.root,
		source_id: plan.source().root_id,
		destination_id: plan.destination().root.id,
	};
	let mut donor_job_id = *plan.attempt().job.as_bytes();
	donor_job_id[15] ^= 1;
	let donor_attempt = PlanAttempt {
		job: JournalJobId::from_bytes(donor_job_id).expect("donor job UUIDv7"),
		job_name: component(DONOR_JOB),
		..plan.attempt()
	};
	let donor = plan_new_file(
		roots,
		donor_attempt,
		plan.source().component,
		component(DONOR_TARGET),
	)
	.expect("plan an independent donor job");
	let profile = CopyProfile {
		id: fixture.profile,
		signer: &fixture.key,
		created: OwnerTimestamp::new(1_700_000_013, 0).expect("fixture timestamp"),
		owner_token: OwnerToken::from_bytes([0xb7; 16]).expect("distinct donor token"),
	};
	copy_new_file(roots, &donor, profile, &mut [0; 7]).expect("commit the donor's real receipt");
	assert_eq!(
		fixture
			.inspect_as(&fixture.key, fixture.profile, DONOR_JOB)
			.expect("authenticate donor using the recipient's trusted profile")
			.disposition,
		RecoveryDisposition::Complete
	);
	fs::read(
		fixture
			.path
			.join(OsStr::from_bytes(DONOR_JOB))
			.join(RECEIPT_FILE),
	)
	.expect("read canonical donor receipt")
}

fn assert_rejects_receipt_without_mutation(fixture: &CopyFixture, path: &Path, foreign: &[u8]) {
	fs::write(path, foreign).expect("transplant the fixture receipt bytes");
	let witnesses: [PathBuf; 6] = [
		fixture.path.join("source"),
		fixture.target(),
		fixture.job().join(OWNER_FILE),
		fixture.job().join(PLAN_FILE),
		fixture.job().join(JOURNAL_FILE),
		path.to_owned(),
	];
	let before = witnesses.each_ref().map(|path| file_snapshot(path));
	assert!(matches!(
		fixture.inspect(),
		Err(RecoveryInspectError::ReceiptBinding)
	));
	assert_eq!(witnesses.each_ref().map(|path| file_snapshot(path)), before);
	assert_absent(&fixture.stage());

	assert!(matches!(
		finish_result(fixture),
		Err(RecoveryFinishError::Inspection(
			RecoveryInspectError::ReceiptBinding
		))
	));
	assert_eq!(witnesses.each_ref().map(|path| file_snapshot(path)), before);
	assert_absent(&fixture.stage());
}

fn file_snapshot(path: &Path) -> (u64, u64, i64, i64, Vec<u8>) {
	let metadata = fs::metadata(path).expect("observe retained fixture inode");
	(
		metadata.dev(),
		metadata.ino(),
		metadata.ctime(),
		metadata.ctime_nsec(),
		fs::read(path).expect("read retained fixture bytes"),
	)
}

fn finish(fixture: &CopyFixture) -> RecoveryInspection {
	finish_result(fixture).expect("finish an authenticated fixture copy")
}

fn finish_result(fixture: &CopyFixture) -> Result<RecoveryInspection, RecoveryFinishError> {
	finish_recovery(
		&fixture.root,
		component(JOB),
		RecoveryProfile {
			id: fixture.profile,
			verifying_key: &fixture.key.verifying_key(),
		},
		&mut [0; 11],
	)
}
