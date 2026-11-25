//! Native Linux coverage for persisted range evidence and fail-closed recovery inspection.

#![cfg(target_os = "linux")]

use std::fs::{self, DirBuilder, File};
use std::io::{ErrorKind, Read as _, Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::SigningKey;
use exacopy_endpoint::UnixComponent;
use exacopy_engine::linux::{
	CopyRoots, RecoveryInspectError, copy_new_file, inspect_recovery, plan_new_file,
};
use exacopy_journal::{
	JournalEntryId, JournalEpoch, JournalJobId, OwnerProfileId, OwnerRecord, OwnerStateDirectory,
	OwnerTimestamp, OwnerToken, RangePage, RootCapabilityId, StreamDigest,
};
use exacopy_platform::linux::{DestinationRoot, ReadRoot};
use exacopy_transfer::linux::{
	CopyProfile, JournalReplay, LocalCopyPlan, PlanAttempt, RecoveryDisposition,
	RecoveryInspection, RecoveryProfile, RecoveryStep, replay_journal,
};

const BLOCK_BYTES: usize = 1024 * 1024;
const FULL_BLOCKS: u8 = 64;
const SOURCE_TAIL: &[u8] = b"distinct tail after the checkpoint threshold";
const SOURCE_LENGTH: u64 = FULL_BLOCKS as u64 * BLOCK_BYTES as u64 + SOURCE_TAIL.len() as u64;
const SOURCE: &str = "source";
const TARGET: &str = "target";
const JOB: &str = "checkpoint-job";
const STAGE: &str = "payload";
const JOURNAL_SEGMENT: &str = "00000000000000000001.exajnl";
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

#[test]
fn copy_commits_exact_range_pages_and_recovery_rejects_damaged_evidence() {
	let fixture = Fixture::new();
	let source = fixture.path.join(SOURCE);
	let target = fixture.path.join(TARGET);
	let source_identity = fs::metadata(&source).expect("observe original source inode");
	let expected = write_source(&source);
	let replay = fixture.copy();
	assert!(
		replay.receipt.is_some(),
		"journal must commit the copy receipt"
	);
	assert!(
		!replay.checkpoints.is_empty(),
		"copy past the byte threshold must persist at least one checkpoint"
	);

	let mut prefix_end = 0_u64;
	for (index, record) in replay.checkpoints.iter().enumerate() {
		let ordinal = u32::try_from(index + 1).expect("checkpoint ordinal fits");
		assert_eq!(record.page.ordinal(), ordinal);
		let encoded = fs::read(fixture.page_path(ordinal)).expect("read referenced range page");
		assert_eq!(encoded.len(), record.page.byte_length());
		let page = RangePage::decode(&encoded).expect("decode canonical range page");
		assert_eq!(page.reference(), record.page);
		assert_eq!(page.source(), record.source);
		assert_eq!(
			page.offset(),
			prefix_end,
			"range {ordinal} must extend the prefix"
		);
		prefix_end = prefix_end
			.checked_add(page.length())
			.expect("range end fits");
		assert!(
			prefix_end <= SOURCE_LENGTH,
			"range {ordinal} must fit within the source"
		);
		let expected_range = digest_range(&source, page.offset(), page.length());
		assert_eq!(page.digest().as_bytes(), expected_range.as_bytes());
	}
	assert_eq!(fixture.disposition(), RecoveryDisposition::Complete);

	let target_identity = fs::metadata(&target).expect("observe published inode");
	let journal_before = fs::read(fixture.journal_path()).expect("snapshot committed journal");
	let first_page = fixture.page_path(1);
	let original = fs::read(&first_page).expect("snapshot first checkpoint page");
	let retained = first_page.with_extension("retained");
	fs::rename(&first_page, &retained).expect("simulate missing referenced page");
	assert!(matches!(
		fixture.inspect(),
		Err(RecoveryInspectError::Platform {
			step: RecoveryStep::Checkpoint,
			..
		})
	));
	assert_absent(&first_page);
	fs::rename(&retained, &first_page).expect("restore original page name");

	let truncated = &original[..original.len() - 1];
	fs::write(&first_page, truncated).expect("simulate a truncated checkpoint page");
	let error = fixture.inspect();
	assert!(
		matches!(error, Err(RecoveryInspectError::Checkpoint(_))),
		"recovery must reject the truncated page, got {error:?}"
	);
	assert_eq!(
		fs::read(&first_page).expect("retain truncated page"),
		truncated
	);

	let page = RangePage::decode(&original).expect("decode first checkpoint page");
	let mut incorrect_digest = *page.digest().as_bytes();
	incorrect_digest[0] ^= 1;
	let incorrect = RangePage::new(
		page.ordinal(),
		page.offset(),
		page.length(),
		StreamDigest::from_bytes(incorrect_digest),
		page.source(),
	)
	.expect("construct a canonical page with a different measured digest")
	.encode();
	assert_eq!(incorrect.len(), original.len());
	fs::write(&first_page, &incorrect).expect("replace referenced page bytes in the test fixture");
	let error = fixture.inspect();
	assert!(
		matches!(error, Err(RecoveryInspectError::CheckpointBinding)),
		"recovery must reject a canonical page with a different reference, got {error:?}"
	);
	assert_eq!(
		fs::read(&first_page).expect("retain rejected page"),
		incorrect
	);

	assert_eq!(
		fs::read(fixture.journal_path()).expect("retain committed journal"),
		journal_before
	);
	let source_after = fs::metadata(&source).expect("retain source inode");
	let target_after = fs::metadata(&target).expect("retain published inode");
	assert_eq!(source_identity.ino(), source_after.ino());
	assert_eq!(target_identity.ino(), target_after.ino());
	assert_ne!(source_after.ino(), target_after.ino());
	assert_eq!(source_after.len(), SOURCE_LENGTH);
	assert_eq!(target_after.len(), SOURCE_LENGTH);
	assert_eq!(digest_range(&source, 0, SOURCE_LENGTH), expected);
	assert_eq!(digest_range(&target, 0, SOURCE_LENGTH), expected);
	assert_absent(
		&fixture
			.job_path()
			.join(OwnerStateDirectory::Stage.name())
			.join(STAGE),
	);
}

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).expect("fixture uses bounded components")
}

fn write_source(path: &Path) -> blake3::Hash {
	let mut file = File::options()
		.write(true)
		.open(path)
		.expect("open fixture source for writing");
	let mut block = vec![0x5a; BLOCK_BYTES];
	let mut hasher = blake3::Hasher::new();
	for index in 0..FULL_BLOCKS {
		block[0] = index;
		file.write_all(&block)
			.expect("write patterned source block");
		hasher.update(&block);
	}
	file.write_all(SOURCE_TAIL).expect("write source tail");
	hasher.update(SOURCE_TAIL);
	hasher.finalize()
}

fn digest_range(path: &Path, offset: u64, length: u64) -> blake3::Hash {
	let mut file = File::open(path).expect("open fixture stream for independent measurement");
	file.seek(SeekFrom::Start(offset))
		.expect("seek to measured range");
	let mut hasher = blake3::Hasher::new();
	let mut range = file.take(length);
	let mut block = [0_u8; 16 * 1024];
	while range.limit() > 0 {
		let count = range.read(&mut block).expect("measure range bytes");
		assert_ne!(count, 0, "measured range must be present in full");
		hasher.update(&block[..count]);
	}
	hasher.finalize()
}

fn assert_absent(path: &Path) {
	assert_eq!(
		fs::symlink_metadata(path)
			.expect_err("fixture path must be absent")
			.kind(),
		ErrorKind::NotFound
	);
}

struct Fixture {
	path: PathBuf,
	destination: DestinationRoot,
	signer: SigningKey,
	profile: OwnerProfileId,
}

impl Fixture {
	fn new() -> Self {
		let path = std::env::temp_dir().join(format!(
			"exacopy-range-checkpoints-{}-{}",
			std::process::id(),
			NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed),
		));
		DirBuilder::new()
			.mode(0o700)
			.create(&path)
			.expect("create private range fixture");
		let destination = DestinationRoot::from_directory(File::open(&path).expect("open fixture"))
			.expect("admit fixture destination root");
		File::create_new(path.join(SOURCE)).expect("create fixture source inode");
		Self {
			path,
			destination,
			signer: SigningKey::from_bytes(&[0x37; 32]),
			profile: OwnerProfileId::from_bytes([0x61; 16]).expect("fixture profile"),
		}
	}

	fn copy(&self) -> JournalReplay {
		let source = ReadRoot::from_directory(File::open(&self.path).expect("open source root"))
			.expect("admit fixture source root");
		let root_id =
			RootCapabilityId::from_bytes([0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 7])
				.expect("fixture root UUIDv4");
		let roots = CopyRoots {
			source: &source,
			destination: &self.destination,
			source_id: root_id,
			destination_id: root_id,
		};
		let attempt = PlanAttempt {
			job: JournalJobId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
				.expect("fixture job UUIDv7"),
			epoch: JournalEpoch::new(1),
			entry: JournalEntryId::from_bytes([0x3a; 16]),
			job_name: component(JOB),
			stage_name: component(STAGE),
		};
		let plan = plan_new_file(roots, attempt, component(SOURCE), component(TARGET))
			.expect("plan copy past the range checkpoint threshold");
		let profile = CopyProfile {
			id: self.profile,
			signer: &self.signer,
			created: OwnerTimestamp::new(1_700_000_013, 0).expect("fixture timestamp"),
			owner_token: OwnerToken::from_bytes([0x5b; 16]).expect("fixture owner token"),
		};
		copy_new_file(roots, &plan, profile, &mut vec![0; BLOCK_BYTES])
			.expect("publish full verified file and commit its receipt");

		let owner = OwnerRecord::decode(
			&fs::read(self.job_path().join("owner.cbor")).expect("read retained owner"),
			self.profile,
			&self.signer.verifying_key(),
		)
		.expect("authenticate retained owner");
		assert!(
			owner
				.manifest()
				.directories
				.contains(&OwnerStateDirectory::Checkpoints)
		);
		let plan_bytes = fs::read(self.job_path().join("plan.cbor")).expect("read retained plan");
		let retained_plan = LocalCopyPlan::decode(&plan_bytes).expect("decode retained plan");
		assert_eq!(retained_plan, plan);
		replay_journal(
			File::open(self.journal_path()).expect("read committed journal"),
			&retained_plan,
			&owner,
		)
		.expect("replay checkpoint records before stage seal and publication")
	}

	fn job_path(&self) -> PathBuf {
		self.path.join(JOB)
	}

	fn journal_path(&self) -> PathBuf {
		self.job_path()
			.join(OwnerStateDirectory::Journal.name())
			.join(JOURNAL_SEGMENT)
	}

	fn page_path(&self, ordinal: u32) -> PathBuf {
		self.job_path()
			.join(OwnerStateDirectory::Checkpoints.name())
			.join(format!("range-{ordinal:010}.cbor"))
	}

	fn inspect(&self) -> Result<RecoveryInspection, RecoveryInspectError> {
		inspect_recovery(
			&self.destination,
			component(JOB),
			RecoveryProfile {
				id: self.profile,
				verifying_key: &self.signer.verifying_key(),
			},
			&mut vec![0; BLOCK_BYTES],
		)
	}

	fn disposition(&self) -> RecoveryDisposition {
		self.inspect()
			.expect("inspect complete copy and authenticated checkpoint pages")
			.disposition
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.path);
	}
}
