use exacopy_transfer::linux::JournalTail;

use std::fs::{self, File, FileTimes, Metadata};
use std::io::Read as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use exacopy_journal::frame::{Frame, FrameKind};
use exacopy_journal::{
	JournalEpoch, LOCAL_RECEIPT_LOCATION, LinuxFileIdentity, MAX_CHECKPOINT_RANGE_BYTES,
	OwnerDigest, PublishIntent, RangeResumeStarted, ReceiptCommitted, ReceiptDigest,
	RootCapabilityId,
};

use super::evidence::{SEGMENT, SUCCESS_ORDER, assert_absent, read_frames};
use super::{
	Checkpoint, DESTINATION_DIRECTORY, Fixture, JOB, STAGE_DIRECTORY, STAGE_FILE, Snapshot, TARGET,
	component, connect_checkpoint, fixture_signer, open_destination, open_source, profile_id,
	source_id, uuid_v4,
};
use crate::assembly::linux::{
	CopyReceipt, RecoveryDisposition, RecoveryInspection, RecoveryProfile, RecoveryRetryError,
	RecoverySource, inspect_recovery, resume_recovery, retry_recovery,
};

pub(super) const CHECKPOINT_PREFIX: &[FrameKind] = &[
	FrameKind::JobPrepared,
	FrameKind::EntryPrepared,
	FrameKind::RangeCheckpoint,
];
pub(super) const RESUMED_PREFIX: &[FrameKind] = &[FrameKind::RecoveryStarted];
const SOURCE_LENGTH: u64 = MAX_CHECKPOINT_RANGE_BYTES + 1;
const SOURCE_TAIL_BYTE: u8 = 0xfd;
const READ_BUFFER_BYTES: usize = 64 * 1024;
const RESUME_BUFFER_BYTES: usize = 1024 * 1024;

#[test]
fn resumes_checkpoint_into_same_inode_and_commits_one_receipt() {
	let (fixture, source_before) = interrupted_copy();
	let stage = identity(
		&stage_path(&fixture)
			.metadata()
			.expect("observe retained inode"),
	);
	let complete = resume(&fixture.0, source_id()).expect("resume from synchronized range");

	assert_successful_resume(&fixture, &source_before, stage, complete, 2, &[]);
	assert_stable_completion(&fixture, complete);
}

#[test]
fn rewrites_corrupt_checkpointed_bytes_before_publishing() {
	let (fixture, source_before) = interrupted_copy();
	let stage_file = File::options()
		.write(true)
		.open(stage_path(&fixture))
		.expect("open retained fixture inode");
	let stage = identity(&stage_file.metadata().expect("observe retained inode"));
	stage_file
		.write_all_at(b"wrong checkpoint data", 0)
		.expect("corrupt bytes inside the first checkpoint");
	stage_file.sync_all().expect("synchronize the corruption");
	drop(stage_file);

	let complete = resume(&fixture.0, source_id()).expect("rewrite the invalid retained range");
	assert_successful_resume(&fixture, &source_before, stage, complete, 2, &[]);
}

#[test]
fn wrong_source_grant_preserves_source_stage_and_journal() {
	let (fixture, _) = interrupted_copy();
	let stage = Snapshot::read(&stage_path(&fixture));
	let source = Snapshot::read(&fixture.source());
	let segment = artifact(&fixture, SEGMENT);
	let invalid_id = RootCapabilityId::from_bytes(uuid_v4(8)).expect("fixture alternative UUID");
	let result = resume(&fixture.0, invalid_id);
	assert!(
		matches!(result, Err(RecoveryRetryError::SourceMismatch)),
		"must reject the current grant despite a matching source inode, got {result:?}"
	);
	assert_eq!(
		artifact(&fixture, SEGMENT),
		segment,
		"resume appended a frame"
	);
	assert_eq!(
		Snapshot::read(&stage_path(&fixture)),
		stage,
		"stage changed"
	);
	assert_eq!(Snapshot::read(&fixture.source()), source, "source changed");
	assert_absent(&fixture.destination().join(TARGET));
	assert_absent(&fixture.job().join(LOCAL_RECEIPT_LOCATION));
}

#[test]
fn changed_live_source_with_the_old_mtime_leaves_the_partial_stage_private() {
	let (fixture, original) = interrupted_copy();
	let source = File::options().write(true).open(fixture.source()).unwrap();
	source.write_all_at(b"\xff", 0).unwrap();
	source
		.set_times(FileTimes::new().set_modified(original.modified().unwrap()))
		.unwrap();
	source.sync_all().unwrap();
	drop(source);
	let changed = fs::metadata(fixture.source()).unwrap();
	assert_eq!(changed.len(), original.len());
	assert_eq!(changed.modified().unwrap(), original.modified().unwrap());
	assert_ne!(
		(changed.ctime(), changed.ctime_nsec()),
		(original.ctime(), original.ctime_nsec())
	);

	let preserved_source = Snapshot::read(&fixture.source());
	let preserved_stage = Snapshot::read(&stage_path(&fixture));
	let prefix = artifact(&fixture, SEGMENT);
	assert!(matches!(
		resume(&fixture.0, source_id()),
		Err(RecoveryRetryError::SourceMismatch)
	));
	assert_eq!(Snapshot::read(&fixture.source()), preserved_source);
	assert_eq!(Snapshot::read(&stage_path(&fixture)), preserved_stage);
	assert_eq!(artifact(&fixture, SEGMENT), prefix);
	assert_absent(&fixture.destination().join(TARGET));
}

#[test]
fn resumes_again_after_resume_start_is_synchronized() {
	assert_pre_intent_restart(Checkpoint::RangeResumeStartedSynced);
}

#[test]
fn resumes_again_after_resumed_data_is_flushed() {
	assert_pre_intent_restart(Checkpoint::RangeResumeDataFlushed);
}

#[test]
fn synchronized_resume_intent_defers_to_retained_publication_retry() {
	let (fixture, source_before) = interrupted_copy();
	let (mut worker, _stream) = fixture.pause_worker(Checkpoint::RangeResumeIntentSynced);
	worker.kill_at(Checkpoint::RangeResumeIntentSynced);
	let stage = Snapshot::read(&stage_path(&fixture));
	assert_absent(&fixture.destination().join(TARGET));
	assert_absent(&fixture.job().join(LOCAL_RECEIPT_LOCATION));
	let frames = read_frames(
		&fixture,
		&[CHECKPOINT_PREFIX, RESUMED_PREFIX, &SUCCESS_ORDER[2..6]].concat(),
	);
	let started = assert_started(
		&fixture,
		&frames,
		CHECKPOINT_PREFIX.len(),
		stage.identity,
		2,
	);
	assert_intent(
		frames.last().expect("retain the synchronized intent"),
		started,
	);
	let segment = artifact(&fixture, SEGMENT);
	let observed = inspect(&fixture);
	assert_eq!(observed.disposition, RecoveryDisposition::PossibleRetry);
	assert_eq!(
		resume(&fixture.0, source_id()).expect("observe the retained publication intent"),
		observed
	);
	assert_eq!(
		artifact(&fixture, SEGMENT),
		segment,
		"resume appended a frame"
	);
	assert_eq!(
		Snapshot::read(&stage_path(&fixture)),
		stage,
		"stage changed"
	);
	assert_absent(&fixture.destination().join(TARGET));

	let complete = retry_recovery(
		&open_destination(&fixture.destination()),
		component(JOB),
		profile(&fixture_signer().verifying_key()),
		RecoverySource {
			root: &open_source(&fixture.0),
			id: source_id(),
		},
		&mut vec![0; RESUME_BUFFER_BYTES],
	)
	.expect("retry the retained publication intent");
	assert_published(&fixture, &source_before, stage.identity, complete, 3);
	assert_stable_completion(&fixture, complete);
}

#[test]
#[ignore = "subprocess entrypoint for the native partial-range resume crash tests"]
fn resume_worker() {
	let root = connect_checkpoint();
	let result = resume(&root, source_id());
	panic!("worker unexpectedly survived a resume checkpoint: {result:?}");
}

fn assert_pre_intent_restart(checkpoint: Checkpoint) {
	let (fixture, source_before) = interrupted_copy();
	let before = stage_path(&fixture)
		.metadata()
		.expect("observe retained inode");
	let stage = identity(&before);
	let (mut worker, _stream) = fixture.pause_worker(checkpoint);
	worker.kill_at(checkpoint);
	let interrupted = read_frames(&fixture, &[CHECKPOINT_PREFIX, RESUMED_PREFIX].concat());
	assert_started(&fixture, &interrupted, CHECKPOINT_PREFIX.len(), stage, 2);
	assert_absent(&fixture.destination().join(TARGET));
	assert_absent(&fixture.job().join(LOCAL_RECEIPT_LOCATION));
	let after = stage_path(&fixture)
		.metadata()
		.expect("observe the retained stage after the resume crash");
	assert_eq!(identity(&after), stage);
	let expected_len = if checkpoint == Checkpoint::RangeResumeDataFlushed {
		SOURCE_LENGTH
	} else {
		before.len()
	};
	assert_eq!(after.len(), expected_len, "stage length at {checkpoint:?}");
	let inspected = inspect(&fixture);
	assert_eq!(
		inspected.disposition,
		RecoveryDisposition::RetainedPreparation
	);
	assert_eq!(
		inspected.journal.head,
		interrupted
			.last()
			.expect("synchronized resume start")
			.head()
	);

	let complete = resume(&fixture.0, source_id()).expect("start a new pre-intent epoch");
	assert_successful_resume(&fixture, &source_before, stage, complete, 3, RESUMED_PREFIX);
}

pub(super) fn assert_successful_resume(
	fixture: &Fixture,
	source: &Metadata,
	stage: LinuxFileIdentity,
	complete: RecoveryInspection,
	epoch: u64,
	interrupted_resume: &[FrameKind],
) {
	assert_published(fixture, source, stage, complete, epoch);
	let frames = read_frames(
		fixture,
		&[
			CHECKPOINT_PREFIX,
			interrupted_resume,
			RESUMED_PREFIX,
			&SUCCESS_ORDER[2..],
		]
		.concat(),
	);
	let started = assert_started(
		fixture,
		&frames,
		CHECKPOINT_PREFIX.len() + interrupted_resume.len(),
		stage,
		epoch,
	);
	let intent = frames
		.iter()
		.find(|frame| frame.kind() == FrameKind::PublishIntent)
		.expect("record publication intent during resume");
	assert_intent(intent, started);
	assert_receipt_bound(fixture, &frames);
}

pub(super) fn interrupted_copy() -> (Fixture, Metadata) {
	let fixture = Fixture::new();
	let source = File::options()
		.write(true)
		.open(fixture.source())
		.expect("open source fixture to set the copy extent");
	source
		.set_len(SOURCE_LENGTH)
		.expect("extend past one range");
	source
		.write_all_at(&[SOURCE_TAIL_BYTE], MAX_CHECKPOINT_RANGE_BYTES)
		.expect("set nonzero data outside the checkpointed prefix");
	source
		.set_times(
			FileTimes::new().set_modified(UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789)),
		)
		.expect("set distinct source mtime");
	let before = source
		.metadata()
		.expect("observe source before interrupted copy");
	drop(source);

	let (mut worker, _stream) = fixture.pause_worker(Checkpoint::RangeFrameSynced);
	worker.kill_at(Checkpoint::RangeFrameSynced);
	read_frames(&fixture, CHECKPOINT_PREFIX);
	let stage = stage_path(&fixture)
		.metadata()
		.expect("observe retained stage");
	assert!(
		(1..=MAX_CHECKPOINT_RANGE_BYTES).contains(&stage.len()),
		"the first checkpoint can be triggered by bytes or time"
	);
	assert_absent(&fixture.destination().join(TARGET));
	(fixture, before)
}

pub(super) fn assert_started(
	fixture: &Fixture,
	frames: &[Frame],
	index: usize,
	stage: LinuxFileIdentity,
	epoch: u64,
) -> RangeResumeStarted {
	let frame = &frames[index];
	assert_eq!(frame.kind().code(), 19, "pre-intent resume discriminator");
	let started = RangeResumeStarted::from_frame(frame).expect("decode pre-intent resume");
	assert_eq!(started.context().epoch, JournalEpoch::new(epoch));
	assert_eq!(started.prior_epoch(), JournalEpoch::new(epoch - 1));
	assert_eq!(started.evidence().preparation, frames[1].head());
	assert_eq!(started.evidence().preceding, frames[index - 1].head());
	assert_eq!(started.evidence().stage, stage);
	let directory = fixture.job().join(STAGE_DIRECTORY);
	let directory = directory
		.metadata()
		.expect("observe retained stage directory");
	assert_eq!(started.evidence().stage_directory, identity(&directory));
	let owner_bytes = artifact(fixture, "owner.cbor");
	assert_eq!(
		started.evidence().authorization,
		OwnerDigest::from_bytes(*blake3::hash(&owner_bytes).as_bytes())
	);
	started
}

pub(super) fn assert_intent(frame: &Frame, started: RangeResumeStarted) {
	let intent = PublishIntent::from_frame(frame).expect("decode synchronized resume intent");
	assert_eq!(intent.context.epoch, started.context().epoch);
	assert_eq!(intent.target.stage, started.evidence().stage);
	assert_eq!(intent.target.component, component(TARGET));
}

fn assert_published(
	fixture: &Fixture,
	source_before: &Metadata,
	stage: LinuxFileIdentity,
	complete: RecoveryInspection,
	epoch: u64,
) {
	assert_eq!(complete.disposition, RecoveryDisposition::Complete);
	assert_eq!(complete.tail, JournalTail::Clean);
	assert_absent(&stage_path(fixture));

	let mut source = File::open(fixture.source()).expect("independently reopen source");
	let mut target = File::open(fixture.destination().join(TARGET))
		.expect("independently reopen published target");
	let source_after = source.metadata().expect("observe source after resume");
	let published = target.metadata().expect("observe published file");
	assert_eq!(identity(&source_after), identity(source_before));
	assert_eq!(source_after.len(), SOURCE_LENGTH);
	assert_eq!(
		(source_after.ctime(), source_after.ctime_nsec()),
		(source_before.ctime(), source_before.ctime_nsec()),
		"copy and recovery must preserve the source"
	);
	assert_eq!(
		identity(&published),
		stage,
		"publish the original stage inode"
	);
	assert_eq!(published.len(), SOURCE_LENGTH);
	assert_eq!(published.mode(), source_before.mode());
	assert_eq!(
		(published.uid(), published.gid()),
		(source_before.uid(), source_before.gid())
	);
	assert_eq!(
		(published.mtime(), published.mtime_nsec()),
		(source_before.mtime(), source_before.mtime_nsec())
	);
	assert_eq!(published.nlink(), 1);

	let digest = assert_streams_equal(&mut source, &mut target);
	let bytes = artifact(fixture, LOCAL_RECEIPT_LOCATION);
	let receipt = CopyReceipt::decode(&bytes).expect("decode the published receipt artifact");
	let evidence = receipt.evidence();
	assert_eq!(evidence.context.epoch, JournalEpoch::new(epoch));
	assert_eq!(evidence.source, identity(source_before));
	assert_eq!(evidence.target, component(TARGET));
	assert_eq!(evidence.stream.identity, stage);
	assert_eq!(evidence.stream.length.get(), SOURCE_LENGTH);
	assert_eq!(evidence.stream.digest.as_bytes(), digest.as_bytes());
}

fn assert_streams_equal(source: &mut File, target: &mut File) -> blake3::Hash {
	let mut source_buffer = vec![0; READ_BUFFER_BYTES];
	let mut target_buffer = vec![0; READ_BUFFER_BYTES];
	let mut hash = blake3::Hasher::new();
	let mut read = 0;
	loop {
		let count = source.read(&mut source_buffer).expect("read source bytes");
		if count == 0 {
			break;
		}
		let target_bytes = &mut target_buffer[..count];
		target
			.read_exact(target_bytes)
			.expect("read published bytes");
		assert!(
			target_bytes == &source_buffer[..count],
			"target and source differ in the chunk starting at byte {read}"
		);
		hash.update(target_bytes);
		read += u64::try_from(count).expect("test read length fits u64");
	}
	assert_eq!(read, SOURCE_LENGTH);
	assert_eq!(target.read(&mut [0]).expect("observe target EOF"), 0);
	hash.finalize()
}

pub(super) fn assert_receipt_bound(fixture: &Fixture, frames: &[Frame]) {
	let [.., durability, committed] = frames else {
		panic!("completed journal must end in a durability observation and receipt commitment");
	};
	let bytes = artifact(fixture, LOCAL_RECEIPT_LOCATION);
	let receipt = CopyReceipt::decode(&bytes).expect("decode the committed receipt artifact");
	ReceiptCommitted::from_frame(committed)
		.expect("decode final receipt commitment")
		.validate_evidence(durability, ReceiptDigest::from_bytes(receipt.digest()))
		.expect("bind the commitment to the exact on-disk receipt");
}

pub(super) fn assert_stable_completion(fixture: &Fixture, complete: RecoveryInspection) {
	let segment = artifact(fixture, SEGMENT);
	let receipt = artifact(fixture, LOCAL_RECEIPT_LOCATION);
	assert_eq!(inspect(fixture), complete);
	assert_eq!(
		resume(&fixture.0, source_id()).expect("repeat resume after completion"),
		complete
	);
	assert_eq!(artifact(fixture, SEGMENT), segment);
	assert_eq!(artifact(fixture, LOCAL_RECEIPT_LOCATION), receipt);
}

pub(super) fn identity(stat: &Metadata) -> LinuxFileIdentity {
	LinuxFileIdentity::new(stat.dev(), stat.ino())
}

pub(super) fn stage_path(fixture: &Fixture) -> PathBuf {
	fixture.job().join(STAGE_DIRECTORY).join(STAGE_FILE)
}

pub(super) fn artifact(fixture: &Fixture, name: &str) -> Vec<u8> {
	fs::read(fixture.job().join(name)).unwrap_or_else(|error| panic!("read {name}: {error}"))
}

fn profile(verifying_key: &VerifyingKey) -> RecoveryProfile<'_> {
	RecoveryProfile {
		id: profile_id(),
		verifying_key,
	}
}

pub(super) fn inspect(fixture: &Fixture) -> RecoveryInspection {
	inspect_recovery(
		&open_destination(&fixture.destination()),
		component(JOB),
		profile(&fixture_signer().verifying_key()),
		&mut vec![0; RESUME_BUFFER_BYTES],
	)
	.expect("inspect the interrupted copy")
}

pub(super) fn resume(
	root: &Path,
	id: RootCapabilityId,
) -> Result<RecoveryInspection, RecoveryRetryError> {
	resume_recovery(
		&open_destination(&root.join(DESTINATION_DIRECTORY)),
		component(JOB),
		profile(&fixture_signer().verifying_key()),
		RecoverySource {
			root: &open_source(root),
			id,
		},
		&mut vec![0; RESUME_BUFFER_BYTES],
	)
}
