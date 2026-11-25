//! Native Linux tests for owner-private job bootstrap and first-frame binding.

#![cfg(target_os = "linux")]

use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use ed25519_dalek::SigningKey;
use exacopy_endpoint::UnixComponent;
use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
use exacopy_journal::{
	DestinationRootBinding, JobPrepared, JournalContext, JournalEpoch, JournalJobId,
	LinuxFileIdentity, OwnerError, OwnerManifest, OwnerProfileId, OwnerRecord, OwnerStateDirectory,
	OwnerTimestamp, OwnerToken, PlanDigest, RootCapabilityId,
};
use exacopy_platform::linux::{DestinationRoot, StageError};
use exacopy_transfer::linux::{JobBootstrap, JobBootstrapError, JobStep, PreparedJob};

const JOB_DIRECTORY: &str = "fixture-job";
const OWNER: &str = "owner.cbor";
const JOURNAL: &str = "journal";
const FIRST_SEGMENT: &str = "00000000000000000001.exajnl";
const STAGE: &str = "stage";
const TARGET: &str = "final-target";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const PERMISSION_BITS: u32 = 0o7777;

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct DestinationFixture(PathBuf);

impl DestinationFixture {
	fn new() -> Self {
		const MAX_ATTEMPTS: usize = 128;
		let parent = std::env::temp_dir();
		for _ in 0..MAX_ATTEMPTS {
			let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
			let path = parent.join(format!(
				"exacopy-bootstrap-{}-{sequence}",
				std::process::id()
			));
			match DirBuilder::new().mode(PRIVATE_DIRECTORY_MODE).create(&path) {
				Ok(()) => return Self(path),
				Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
				Err(error) => panic!("create private job bootstrap fixture: {error}"),
			}
		}
		panic!("unable to reserve a private job bootstrap fixture");
	}

	fn open_root(&self) -> DestinationRoot {
		let held = File::open(&self.0).expect("open synthetic destination directory");
		DestinationRoot::from_directory(held).expect("admit synthetic destination")
	}

	fn path(&self, name: &str) -> PathBuf {
		self.0.join(name)
	}
}

impl Drop for DestinationFixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}

fn bootstrap(name: &str) -> JobBootstrap<'_> {
	JobBootstrap {
		name: UnixComponent::new(name.as_bytes()).expect("valid synthetic job name"),
		context: JournalContext {
			job: JournalJobId::from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
				.expect("synthetic job UUIDv7"),
			epoch: JournalEpoch::new(23),
			plan_digest: PlanDigest::from_bytes([0x71; 32]),
		},
		destination_id: RootCapabilityId::from_bytes([
			0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 2,
		])
		.expect("synthetic root UUIDv4"),
		profile: OwnerProfileId::from_bytes([0x34; 16]).expect("synthetic profile identity"),
		created: OwnerTimestamp::new(1_700_000_000, 123_456_789).expect("synthetic timestamp"),
		owner_token: OwnerToken::from_bytes([0x72; 16]).expect("synthetic owner token"),
	}
}

fn fixture_signer() -> SigningKey {
	// Deterministic test-only key, unrelated to any profile credentials.
	SigningKey::from_bytes(&[0x57; 32])
}

fn native_identity(metadata: &Metadata) -> LinuxFileIdentity {
	LinuxFileIdentity::new(metadata.dev(), metadata.ino())
}

fn assert_absent(path: &Path) {
	assert_eq!(
		fs::symlink_metadata(path)
			.expect_err("fixture entry must be absent")
			.kind(),
		ErrorKind::NotFound,
		"{path:?}"
	);
}

#[test]
fn verifies_the_persisted_signed_owner_and_first_preparation_frame() {
	let fixture = DestinationFixture::new();
	let destination = fixture.open_root();
	let destination_metadata = fs::metadata(&fixture.0).expect("read destination metadata");
	let request = bootstrap(JOB_DIRECTORY);
	let signer = fixture_signer();
	let job =
		PreparedJob::create(&destination, request, &signer).expect("bootstrap the private job");

	let job_path = fixture.path(JOB_DIRECTORY);
	let journal_path = job_path.join(JOURNAL);
	let stage_path = job_path.join(STAGE);
	let job_metadata = fs::symlink_metadata(&job_path).expect("read job root metadata");
	let journal_metadata =
		fs::symlink_metadata(&journal_path).expect("read journal directory metadata");
	for metadata in [&job_metadata, &journal_metadata] {
		assert!(metadata.is_dir());
		assert_eq!(metadata.mode() & PERMISSION_BITS, PRIVATE_DIRECTORY_MODE);
		assert_eq!(metadata.uid(), destination_metadata.uid());
	}
	assert_absent(&stage_path);
	assert_absent(&fixture.path(TARGET));

	let owner_path = job_path.join(OWNER);
	let owner_bytes = fs::read(&owner_path).expect("read persisted owner record from disk");
	let decoded_owner = OwnerRecord::decode(&owner_bytes, request.profile, &signer.verifying_key())
		.expect("authenticate owner record with the fixture profile and public key");
	assert_eq!(
		decoded_owner.manifest(),
		&OwnerManifest {
			token: request.owner_token,
			job: request.context.job,
			profile: request.profile,
			created: request.created,
			destination_device: destination_metadata.dev(),
			state_root: native_identity(&job_metadata),
			plan_digest: request.context.plan_digest,
			directories: vec![OwnerStateDirectory::Journal, OwnerStateDirectory::Stage],
		},
	);
	assert_eq!(job.owner().as_bytes(), owner_bytes);

	let segment_path = journal_path.join(FIRST_SEGMENT);
	let segment = File::open(&segment_path).expect("reopen first segment independently");
	let segment_metadata = segment.metadata().expect("inspect first segment");
	for metadata in [
		fs::symlink_metadata(owner_path).expect("inspect owner record"),
		segment_metadata.clone(),
	] {
		assert!(metadata.is_file());
		assert_eq!(metadata.mode() & PERMISSION_BITS, PRIVATE_FILE_MODE);
		assert_eq!(metadata.nlink(), 1);
	}
	let start = ChainHead::start();
	let mut reader = FrameReader::new(segment, start);
	let frame = reader
		.next_frame()
		.expect("verify first frame integrity")
		.expect("find JobPrepared frame");
	let prepared = JobPrepared::from_frame(&frame).expect("parse the durable JobPrepared body");
	assert_eq!(
		prepared,
		JobPrepared {
			context: request.context,
			owner_digest: decoded_owner.digest(),
			destination_root: DestinationRootBinding {
				id: request.destination_id,
				identity: native_identity(&destination_metadata),
			},
		},
	);
	assert_eq!(frame.previous_digest(), start.digest());
	assert_eq!(frame.head().sequence(), 1);
	assert_eq!(frame.head(), job.initial_frame().head());
	assert_eq!(job.initial_frame().kind(), FrameKind::JobPrepared);
	assert!(
		reader
			.next_frame()
			.expect("finish reading first segment")
			.is_none()
	);
	assert_eq!(reader.offset(), segment_metadata.len());

	let stage = job
		.create_stage_directory()
		.expect("create the nested private stage");
	let observed_stage =
		fs::symlink_metadata(&stage_path).expect("inspect nested stage while held");
	assert!(observed_stage.is_dir());
	assert_eq!(
		observed_stage.mode() & PERMISSION_BITS,
		PRIVATE_DIRECTORY_MODE
	);
	let identity = stage.identity();
	assert_eq!(
		native_identity(&observed_stage),
		LinuxFileIdentity::new(identity.device(), identity.inode())
	);
	assert!(matches!(
		job.create_stage_directory(),
		Err(StageError::AlreadyExists)
	));
	assert_absent(&fixture.path(STAGE));
	assert_absent(&fixture.path(TARGET));
}

#[test]
fn a_repeated_bootstrap_preserves_the_original_owner_and_journal_records() {
	let fixture = DestinationFixture::new();
	let destination = fixture.open_root();
	let request = bootstrap(JOB_DIRECTORY);
	let signer = fixture_signer();
	let job =
		PreparedJob::create(&destination, request, &signer).expect("bootstrap the original job");
	let job_path = fixture.path(JOB_DIRECTORY);
	let paths = [
		job_path.join(OWNER),
		job_path.join(JOURNAL).join(FIRST_SEGMENT),
	];
	let originals = paths.each_ref().map(|path| {
		(
			native_identity(&fs::symlink_metadata(path).expect("inspect original record")),
			fs::read(path).expect("read original record bytes"),
		)
	});

	let error = PreparedJob::create(&destination, request, &signer)
		.expect_err("refuse the repeated bootstrap");
	assert!(
		matches!(
			error,
			JobBootstrapError::Platform {
				step: JobStep::CreateJob,
				source: StageError::AlreadyExists
			}
		),
		"{error}"
	);
	for (path, (identity, bytes)) in paths.iter().zip(originals) {
		assert_eq!(
			native_identity(&fs::symlink_metadata(path).expect("inspect preserved record")),
			identity
		);
		assert_eq!(fs::read(path).expect("read preserved record bytes"), bytes);
	}
	assert_eq!(job.initial_frame().head().sequence(), 1);
	assert_absent(&fixture.path(TARGET));
}

#[test]
fn a_private_looking_incumbent_job_is_never_adopted() {
	let fixture = DestinationFixture::new();
	let destination = fixture.open_root();
	let path = fixture.path(JOB_DIRECTORY);
	DirBuilder::new()
		.mode(PRIVATE_DIRECTORY_MODE)
		.create(&path)
		.expect("create private-looking incumbent");
	let owner = path.join(OWNER);
	let payload = b"unrelated private record";
	let mut record = OpenOptions::new()
		.create_new(true)
		.write(true)
		.mode(PRIVATE_FILE_MODE)
		.open(&owner)
		.expect("create incumbent record");
	record.write_all(payload).expect("write incumbent record");
	let original = native_identity(&record.metadata().expect("inspect original record"));

	let error = PreparedJob::create(&destination, bootstrap(JOB_DIRECTORY), &fixture_signer())
		.expect_err("reject private-looking incumbent");
	assert!(
		matches!(
			error,
			JobBootstrapError::Platform {
				step: JobStep::CreateJob,
				source: StageError::AlreadyExists
			}
		),
		"{error}"
	);
	assert_eq!(
		native_identity(&fs::symlink_metadata(&owner).expect("inspect retained incumbent record")),
		original
	);
	assert_eq!(
		fs::read(owner).expect("read retained incumbent record"),
		payload
	);
	assert_absent(&path.join(JOURNAL));
	assert_absent(&path.join(STAGE));
	assert_absent(&fixture.path(TARGET));
}

#[test]
fn a_token_reusing_the_job_or_profile_identity_is_rejected_before_creation() {
	let fixture = DestinationFixture::new();
	let destination = fixture.open_root();
	let signer = fixture_signer();
	let request = bootstrap(JOB_DIRECTORY);
	for reused in [request.context.job.as_bytes(), request.profile.as_bytes()] {
		let invalid = JobBootstrap {
			owner_token: OwnerToken::from_bytes(*reused).expect("nonzero identity bytes"),
			..request
		};
		let error = PreparedJob::create(&destination, invalid, &signer)
			.expect_err("require independently assigned owner token");
		assert!(
			matches!(error, JobBootstrapError::Owner(OwnerError::InvalidToken)),
			"{error}"
		);
		assert_absent(&fixture.path(JOB_DIRECTORY));
	}
	assert_absent(&fixture.path(TARGET));
}
