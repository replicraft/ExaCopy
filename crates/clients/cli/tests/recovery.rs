//! Read-only reconciliation against actual Linux copy artifacts and altered evidence.

#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File};
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::SigningKey;
use exacopy_cli::assembly::linux::{
	CopyRoots, RecoveryInspectError, copy_new_file, inspect_recovery, plan_new_file,
};
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
use exacopy_journal::{
	JournalEntryId, JournalEpoch, JournalJobId, OwnerError, OwnerProfileId, OwnerTimestamp,
	OwnerToken, RootCapabilityId,
};
use exacopy_platform::linux::{DestinationRoot, ReadRoot};
use exacopy_transfer::linux::{
	CopyProfile, JournalTail, MAX_LOCAL_COPY_PLAN_BYTES, PlanAttempt, RecoveryDisposition,
	RecoveryInspection, RecoveryIssue, RecoveryProfile, RecoveryStep,
};

const DATA: &[u8] = b"owner-private evidence checks the bytes of this copied file";
const JOB: &[u8] = b"test-job-\xfe";
const TARGET: &[u8] = b"target-\xff";
const STAGE: &[u8] = b"payload";
const OWNER_FILE: &str = "owner.cbor";
const PLAN_FILE: &str = "plan.cbor";
const RECEIPT_FILE: &str = "receipts/receipt.cbor";
const JOURNAL_FILE: &str = "journal/00000000000000000001.exajnl";
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct CopyFixture {
	path: PathBuf,
	root: DestinationRoot,
	key: SigningKey,
	profile: OwnerProfileId,
}

impl CopyFixture {
	fn new() -> Self {
		let path = std::env::temp_dir().join(format!(
			"exacopy-recovery-{}-{}",
			std::process::id(),
			NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed),
		));
		DirBuilder::new()
			.mode(0o700)
			.create(&path)
			.expect("create private fixture destination");
		let root = DestinationRoot::from_directory(File::open(&path).expect("open fixture root"))
			.expect("admit fixture destination");
		let fixture = Self {
			path,
			root,
			key: SigningKey::from_bytes(&[0x37; 32]),
			profile: OwnerProfileId::from_bytes([0x61; 16]).expect("fixture profile"),
		};
		fixture.copy();
		fixture
	}

	fn copy(&self) {
		fs::write(self.path.join("source"), DATA).expect("write independent source");
		let source = ReadRoot::from_directory(File::open(&self.path).expect("open fixture source"))
			.expect("admit fixture source");
		let root_id =
			RootCapabilityId::from_bytes([0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 7])
				.expect("fixture root UUIDv4");
		let roots = CopyRoots {
			source: &source,
			destination: &self.root,
			source_id: root_id,
			destination_id: root_id,
		};
		let attempt = PlanAttempt {
			job: JournalJobId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
				.expect("fixture job UUIDv7"),
			epoch: JournalEpoch::new(2),
			entry: JournalEntryId::from_bytes([0x3a; 16]),
			job_name: component(JOB),
			stage_name: component(STAGE),
		};
		let plan = plan_new_file(roots, attempt, component(b"source"), component(TARGET))
			.expect("prepare the bound local plan");
		let profile = CopyProfile {
			id: self.profile,
			signer: &self.key,
			created: OwnerTimestamp::new(1_700_000_013, 0).expect("fixture timestamp"),
			owner_token: OwnerToken::from_bytes([0x5b; 16]).expect("fixture owner token"),
		};
		copy_new_file(roots, &plan, profile, &mut [0; 7]).expect("complete actual copy");
	}

	fn job(&self) -> PathBuf {
		self.path.join(OsStr::from_bytes(JOB))
	}

	fn target(&self) -> PathBuf {
		self.path.join(OsStr::from_bytes(TARGET))
	}

	fn stage(&self) -> PathBuf {
		self.job().join("stage").join(OsStr::from_bytes(STAGE))
	}

	fn restore_stage(&self) {
		fs::rename(self.target(), self.stage()).expect("reconstruct pre-publication stage binding");
	}

	fn inspect(&self) -> Result<RecoveryInspection, RecoveryInspectError> {
		self.inspect_as(&self.key, self.profile, JOB)
	}

	fn inspect_as(
		&self,
		key: &SigningKey,
		profile: OwnerProfileId,
		name: &[u8],
	) -> Result<RecoveryInspection, RecoveryInspectError> {
		inspect_recovery(
			&self.root,
			component(name),
			RecoveryProfile {
				id: profile,
				verifying_key: &key.verifying_key(),
			},
			&mut [0; 7],
		)
	}

	fn disposition(&self) -> RecoveryDisposition {
		self.inspect().expect("inspect stable evidence").disposition
	}

	fn cut_after(&self, kind: FrameKind, torn_bytes: u64) {
		let path = self.job().join(JOURNAL_FILE);
		let file = File::open(&path).expect("read complete journal");
		let mut reader = FrameReader::new(file, ChainHead::start());
		loop {
			let frame = reader
				.next_frame()
				.expect("read checked frame")
				.expect("find fixture record kind");
			if frame.kind() == kind {
				break;
			}
		}
		fs::OpenOptions::new()
			.write(true)
			.open(path)
			.expect("open synthetic cut")
			.set_len(reader.offset() + torn_bytes)
			.expect("cut journal at chosen boundary");
	}
}

impl Drop for CopyFixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.path);
	}
}

fn component(raw: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(raw).expect("admitted fixture component")
}

fn assert_absent(path: &Path) {
	assert_eq!(
		fs::symlink_metadata(path).expect_err("missing path").kind(),
		ErrorKind::NotFound
	);
}

#[test]
fn inspects_actual_copy_with_a_committed_receipt_and_preserves_artifacts() {
	let fixture = CopyFixture::new();
	let journal = fixture.job().join(JOURNAL_FILE);
	let before = fs::read(&journal).expect("snapshot journal for preservation check");
	let result = fixture.inspect().expect("inspect completed copy");
	assert_eq!(result.disposition, RecoveryDisposition::Complete);
	assert_eq!(result.tail, JournalTail::Clean);
	assert_eq!(result.journal.offset, before.len() as u64);
	assert_eq!(fixture.inspect().expect("repeat the inspection"), result);
	assert_eq!(fs::read(journal).expect("unchanged journal"), before);
	assert_eq!(fs::read(fixture.target()).expect("preserved target"), DATA);
	assert_eq!(
		fs::read(fixture.path.join("source")).expect("preserved source"),
		DATA
	);
	assert_absent(&fixture.stage());
}

#[test]
fn prepublication_prefixes_distinguish_preparation_intent_and_torn_evidence() {
	use RecoveryDisposition::{PossibleRetry, RequiresReconciliation, RetainedPreparation};

	let cases = [
		(FrameKind::MetadataRecorded, 0, RetainedPreparation),
		(FrameKind::PublishIntent, 0, PossibleRetry),
		(
			FrameKind::PublishIntent,
			1,
			RequiresReconciliation(RecoveryIssue::TornJournal),
		),
	];
	for (kind, torn_bytes, expected) in cases {
		let fixture = CopyFixture::new();
		fixture.restore_stage();
		fixture.cut_after(kind, torn_bytes);
		fs::remove_file(fixture.job().join(RECEIPT_FILE)).expect("remove later synthetic receipt");
		let result = fixture.inspect().expect("inspect journal prefix");
		assert_eq!(result.disposition, expected);
		assert_eq!(
			result.tail,
			if torn_bytes == 0 {
				JournalTail::Clean
			} else {
				JournalTail::Torn { bytes_read: 1 }
			},
		);
		assert_absent(&fixture.target());
		assert_eq!(
			fs::read(fixture.stage()).expect("retain all stage bytes"),
			DATA
		);
	}
}

#[test]
fn postpublication_prefixes_distinguish_barriers_and_an_uncommitted_receipt() {
	use RecoveryDisposition::{PublishedNeedsBarriers, PublishedNeedsReceipt};

	let cases = [
		(FrameKind::PublishIntent, false, PublishedNeedsBarriers),
		(
			FrameKind::DurabilityRecorded,
			false,
			PublishedNeedsReceipt {
				artifact_present: false,
			},
		),
		(
			FrameKind::DurabilityRecorded,
			true,
			PublishedNeedsReceipt {
				artifact_present: true,
			},
		),
	];
	for (kind, keep_receipt, expected) in cases {
		let fixture = CopyFixture::new();
		fixture.cut_after(kind, 0);
		if !keep_receipt {
			fs::remove_file(fixture.job().join(RECEIPT_FILE))
				.expect("remove later synthetic receipt");
		}
		assert_eq!(fixture.disposition(), expected);
		assert_eq!(
			fs::read(fixture.target()).expect("retain published bytes"),
			DATA
		);
		assert_absent(&fixture.stage());
	}
}

#[test]
fn keeps_unrelated_target_even_when_the_verified_stage_is_still_private() {
	let fixture = CopyFixture::new();
	fixture.restore_stage();
	fixture.cut_after(FrameKind::PublishIntent, 0);
	fs::remove_file(fixture.job().join(RECEIPT_FILE)).expect("remove later synthetic receipt");
	fs::write(fixture.target(), b"unrelated incumbent").expect("insert unrelated target");
	assert_eq!(fixture.disposition(), RecoveryDisposition::Conflict);
	assert_eq!(
		fs::read(fixture.target()).expect("retain incumbent"),
		b"unrelated incumbent"
	);
	assert_eq!(fs::read(fixture.stage()).expect("retain stage"), DATA);
}

#[test]
fn compares_the_actual_stream_and_current_metadata_even_after_committed_receipt() {
	use RecoveryDisposition::RequiresReconciliation;

	let fixture = CopyFixture::new();
	fs::write(fixture.target(), vec![0; DATA.len()]).expect("change target bytes in place");
	assert_eq!(
		fixture.disposition(),
		RequiresReconciliation(RecoveryIssue::StreamMismatch),
	);
	let fixture = CopyFixture::new();
	fs::set_permissions(fixture.target(), fs::Permissions::from_mode(0o400))
		.expect("change current mode while keeping it readable");
	assert_eq!(
		fixture.disposition(),
		RequiresReconciliation(RecoveryIssue::MetadataMismatch),
	);
	let fixture = CopyFixture::new();
	rustix::fs::setxattr(
		fixture.target(),
		"user.exacopy-test",
		b"test",
		rustix::fs::XattrFlags::CREATE,
	)
	.expect("add visible attribute to the published target");
	assert_eq!(
		fixture.disposition(),
		RequiresReconciliation(RecoveryIssue::MetadataMismatch),
	);
}

#[test]
fn rejects_absent_or_inexact_receipts_and_replaced_stage_directory() {
	use RecoveryDisposition::RequiresReconciliation;

	let fixture = CopyFixture::new();
	let artifact = fixture.job().join(RECEIPT_FILE);
	let mut bytes = fs::read(&artifact).expect("read exact receipt");
	bytes.push(0);
	fs::write(&artifact, bytes).expect("modify exact artifact bytes");
	assert!(matches!(
		fixture.inspect(),
		Err(RecoveryInspectError::Receipt(_))
	));
	fs::remove_file(artifact).expect("remove committed receipt");
	assert_eq!(
		fixture.disposition(),
		RequiresReconciliation(RecoveryIssue::MissingCommittedReceipt),
	);

	let fixture = CopyFixture::new();
	let directory = fixture.stage().parent().expect("stage parent").to_owned();
	fs::rename(&directory, fixture.job().join("old-stage"))
		.expect("detach original stage directory while retaining it");
	DirBuilder::new()
		.mode(0o700)
		.create(directory)
		.expect("create unrelated private stage directory");
	assert_eq!(
		fixture.disposition(),
		RequiresReconciliation(RecoveryIssue::StageDirectoryBinding),
	);
}

#[test]
fn checks_trusted_profile_exact_job_name_and_record_sizes() {
	let fixture = CopyFixture::new();
	let wrong_key = SigningKey::from_bytes(&[0x83; 32]);
	let wrong_profile = OwnerProfileId::from_bytes([0x67; 16]).expect("distinct trusted profile");
	assert!(matches!(
		fixture.inspect_as(&wrong_key, fixture.profile, JOB),
		Err(RecoveryInspectError::Owner(OwnerError::UntrustedKey))
	));
	assert!(matches!(
		fixture.inspect_as(&fixture.key, wrong_profile, JOB),
		Err(RecoveryInspectError::Owner(OwnerError::UntrustedProfile))
	));
	let renamed = b"renamed-job";
	fs::rename(fixture.job(), fixture.path.join(OsStr::from_bytes(renamed)))
		.expect("rename the same authenticated private directory");
	assert!(matches!(
		fixture.inspect_as(&fixture.key, fixture.profile, renamed),
		Err(RecoveryInspectError::PlanBinding)
	));
	fs::rename(fixture.path.join(OsStr::from_bytes(renamed)), fixture.job())
		.expect("restore the correct job name");
	fs::write(
		fixture.job().join(PLAN_FILE),
		vec![0; MAX_LOCAL_COPY_PLAN_BYTES + 1],
	)
	.expect("create an oversize plan artifact");
	assert!(matches!(
		fixture.inspect(),
		Err(RecoveryInspectError::Oversize(RecoveryStep::Plan))
	));

	let fixture = CopyFixture::new();
	fs::write(fixture.job().join(OWNER_FILE), b"invalid owner").expect("damage fixture owner");
	assert!(matches!(
		fixture.inspect(),
		Err(RecoveryInspectError::Owner(_))
	));
}

#[test]
fn validates_the_exact_durability_reference_even_for_uncommitted_receipts() {
	use exacopy_transfer::linux::CopyReceipt;

	let fixture = CopyFixture::new();
	fixture.cut_after(FrameKind::DurabilityRecorded, 0);
	let path = fixture.job().join(RECEIPT_FILE);
	let mut bytes = fs::read(&path).expect("read canonical receipt");
	let anchor = CopyReceipt::decode(&bytes)
		.expect("decode fixture receipt")
		.durability_frame()
		.digest();
	let start = bytes
		.windows(anchor.len())
		.position(|value| value == anchor)
		.expect("find exact durability digest in fixture receipt");
	bytes[start] ^= 1;
	CopyReceipt::decode(&bytes).expect("altered evidence retains canonical receipt encoding");
	fs::write(path, bytes).expect("persist altered durability binding");
	assert!(matches!(
		fixture.inspect(),
		Err(RecoveryInspectError::ReceiptBinding)
	));
}

#[test]
fn distinguishes_missing_objects_from_replaced_private_objects() {
	use RecoveryDisposition::RequiresReconciliation;

	let fixture = CopyFixture::new();
	fixture.cut_after(FrameKind::PublishIntent, 0);
	fs::remove_file(fixture.job().join(RECEIPT_FILE)).expect("remove later synthetic receipt");
	fs::rename(fixture.target(), fixture.path.join("retained-elsewhere"))
		.expect("retain the inode outside both planned names");
	assert_eq!(
		fixture.disposition(),
		RequiresReconciliation(RecoveryIssue::MissingStageAndTarget),
	);
	fs::write(fixture.stage(), DATA).expect("write identical bytes into a different stage inode");
	assert_eq!(
		fixture.disposition(),
		RequiresReconciliation(RecoveryIssue::UnrecognizedStage),
	);
}

#[test]
fn rejects_a_job_held_by_an_active_writer_and_reopens_after_release() {
	use exacopy_platform::linux::StageError;
	use rustix::fs::{FlockOperation, flock};

	let fixture = CopyFixture::new();
	let writer = File::open(fixture.job()).expect("open the synthetic writer's job directory");
	flock(&writer, FlockOperation::NonBlockingLockExclusive).expect("simulate live writer lease");
	assert!(matches!(
		fixture.inspect(),
		Err(RecoveryInspectError::Platform {
			step: RecoveryStep::Lease,
			source: StageError::JobBusy,
		})
	));
	drop(writer);
	assert_eq!(fixture.disposition(), RecoveryDisposition::Complete);
}

#[path = "recovery/finish.rs"]
mod finish;

#[path = "recovery/retry.rs"]
mod retry;
