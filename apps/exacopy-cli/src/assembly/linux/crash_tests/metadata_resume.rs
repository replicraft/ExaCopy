use exacopy_transfer::linux::JournalTail;

use std::fs::{self, File, FileTimes, Metadata, Permissions};
use std::os::unix::fs::{FileExt as _, MetadataExt as _, PermissionsExt as _};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
use exacopy_journal::{EntryPrepared, JournalEpoch, LOCAL_RECEIPT_LOCATION, LinuxFileIdentity};

use super::evidence::{SEGMENT, SUCCESS_ORDER, assert_absent, read_frames};
use super::resume::{
	CHECKPOINT_PREFIX, RESUMED_PREFIX, artifact, assert_intent, assert_receipt_bound,
	assert_stable_completion, assert_started, assert_successful_resume, identity, inspect,
	interrupted_copy, resume, stage_path,
};
use super::{
	Checkpoint, Fixture, METADATA_CHECKPOINTS, SOURCE_BYTES, Snapshot, TARGET, component,
	connect_checkpoint, run_copy_worker, source_id,
};
use crate::assembly::linux::{CopyReceipt, RecoveryDisposition, RecoveryRetryError, StageFailure};

const SOURCE_MODE: u32 = 0o640;
const PERMISSION_BITS: u32 = 0o7777;
const PREPARATION_PREFIX: &[FrameKind] = &[FrameKind::JobPrepared, FrameKind::EntryPrepared];
const SOURCE_ATIME: Duration = Duration::new(1_700_000_001, 123_456_789);
const SOURCE_MTIME: Duration = Duration::new(1_700_000_002, 987_654_321);
const PARTIAL_MTIME: Duration = Duration::new(1_700_000_003, 12_345_678);

#[test]
fn resumes_short_copy_after_metadata_without_any_range_checkpoint() {
	let (fixture, source, source_metadata, stage) = interrupted_short_copy();

	assert_short_resume(&fixture, &source, &source_metadata, stage);
}

#[test]
fn restarts_a_short_private_stage_under_a_fresh_epoch_without_checkpoints() {
	let (fixture, source, source_metadata, stage) = interrupted_short_copy();
	let path = stage_path(&fixture);
	fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
	File::options()
		.write(true)
		.open(&path)
		.unwrap()
		.set_len(1)
		.unwrap();
	assert_short_resume(&fixture, &source, &source_metadata, stage);
}

#[test]
fn restores_journaled_times_after_partial_stage_metadata_application() {
	let (fixture, source, source_metadata, stage) = interrupted_short_copy();
	let file = File::options()
		.write(true)
		.open(stage_path(&fixture))
		.expect("open the disposable retained stage to simulate partial timestamp application");
	file.set_times(FileTimes::new().set_modified(UNIX_EPOCH + PARTIAL_MTIME))
		.expect("change only the stage mtime");
	file.sync_all()
		.expect("synchronize the changed stage mtime");
	let partial = file.metadata().expect("observe partial stage metadata");
	assert_eq!(identity(&partial), stage);
	assert_eq!(partial.mode() & PERMISSION_BITS, SOURCE_MODE);
	assert_eq!(partial.accessed().unwrap(), journaled_access_time(&fixture));
	assert_ne!(
		partial.modified().unwrap(),
		source_metadata.modified().unwrap()
	);
	drop(file);

	assert_short_resume(&fixture, &source, &source_metadata, stage);
}

#[test]
fn refuses_same_length_corruption_in_a_metadata_applied_stage() {
	let (fixture, source, source_metadata, stage) = interrupted_short_copy();
	let path = stage_path(&fixture);
	let file = File::options()
		.write(true)
		.open(&path)
		.expect("open only the disposable retained stage for corruption");
	file.write_all_at(&[SOURCE_BYTES[0] ^ u8::MAX], 0)
		.expect("corrupt the first byte without changing the extent");
	file.set_times(
		FileTimes::new()
			.set_accessed(journaled_access_time(&fixture))
			.set_modified(source_metadata.modified().unwrap()),
	)
	.expect("preserve the intended stage timestamps");
	file.sync_all().expect("synchronize the corrupted stage");
	let retained = file.metadata().expect("observe the corrupted stage");
	assert_eq!(identity(&retained), stage);
	assert_eq!(retained.len(), source_metadata.len());
	assert_source_metadata(&fixture, &retained, &source_metadata);
	drop(file);
	let corrupt = Snapshot::read(&path);
	let segment = artifact(&fixture, SEGMENT);

	let result = resume(&fixture.0, source_id());
	assert!(
		matches!(
			result,
			Err(RecoveryRetryError::ResumeStage(
				StageFailure::DigestMismatch
			))
		),
		"resume must refuse to publish the corrupted stage, got {result:?}"
	);
	assert_eq!(Snapshot::read(&path), corrupt, "corrupted stage changed");
	assert_source_metadata(
		&fixture,
		&fs::metadata(&path).expect("stat preserved stage"),
		&source_metadata,
	);
	assert_eq!(Snapshot::read(&fixture.source()), source, "source changed");
	assert_eq!(artifact(&fixture, SEGMENT), segment, "journal changed");
	assert_private_preparation(&fixture);
}

#[test]
fn resumes_checkpoint_in_a_fresh_epoch_after_resumed_metadata_application() {
	let (fixture, source_metadata) = interrupted_copy();
	let stage = identity(&fs::metadata(stage_path(&fixture)).expect("observe retained inode"));
	let checkpoint = Checkpoint::RangeResumeMetadataApplied;
	let (mut worker, _stream) = fixture.pause_worker(checkpoint);
	worker.kill_at(checkpoint);

	let retained =
		fs::metadata(stage_path(&fixture)).expect("observe stage after resumed metadata");
	assert_eq!(identity(&retained), stage);
	assert_eq!(retained.len(), source_metadata.len());
	assert_source_metadata(&fixture, &retained, &source_metadata);
	let interrupted = read_frames(&fixture, &[CHECKPOINT_PREFIX, RESUMED_PREFIX].concat());
	assert_started(&fixture, &interrupted, CHECKPOINT_PREFIX.len(), stage, 2);
	assert_private_preparation(&fixture);

	let complete = resume(&fixture.0, source_id()).expect("resume the same stage under epoch 3");
	let published =
		fs::metadata(fixture.destination().join(TARGET)).expect("observe published file");
	assert_source_metadata(&fixture, &published, &source_metadata);
	assert_successful_resume(
		&fixture,
		&source_metadata,
		stage,
		complete,
		3,
		RESUMED_PREFIX,
	);
	assert_stable_completion(&fixture, complete);
}

#[test]
#[ignore = "subprocess entrypoint for the native copy metadata crash tests"]
fn copy_metadata_worker() {
	METADATA_CHECKPOINTS.set(true);
	let result = run_copy_worker(&mut [0; 11]);
	panic!("worker unexpectedly survived the copy metadata checkpoint: {result:?}");
}

#[test]
#[ignore = "subprocess entrypoint for the native resume metadata crash tests"]
fn resume_metadata_worker() {
	METADATA_CHECKPOINTS.set(true);
	let root = connect_checkpoint();
	let result = resume(&root, source_id());
	panic!("worker unexpectedly survived the resume metadata checkpoint: {result:?}");
}

fn interrupted_short_copy() -> (Fixture, Snapshot, Metadata, LinuxFileIdentity) {
	let fixture = Fixture::new();
	let file = File::options()
		.write(true)
		.open(fixture.source())
		.expect("open the synthetic source to set initial timestamps");
	file.set_times(
		FileTimes::new()
			.set_accessed(UNIX_EPOCH + SOURCE_ATIME)
			.set_modified(UNIX_EPOCH + SOURCE_MTIME),
	)
	.expect("set distinct source timestamps with subsecond precision");
	let source_metadata = file.metadata().expect("observe the source before copy");
	drop(file);
	let source = Snapshot::read(&fixture.source());
	let checkpoint = Checkpoint::CopyMetadataApplied;
	let (mut worker, _stream) = fixture.pause_worker(checkpoint);
	worker.kill_at(checkpoint);

	let path = stage_path(&fixture);
	let retained = fs::metadata(&path).expect("observe retained stage after initial metadata");
	assert_source_metadata(&fixture, &retained, &source_metadata);
	Snapshot::read(&path).assert_copied_from(&source);
	read_frames(&fixture, PREPARATION_PREFIX);
	assert_private_preparation(&fixture);
	(fixture, source, source_metadata, identity(&retained))
}

fn assert_private_preparation(fixture: &Fixture) {
	assert_absent(&fixture.destination().join(TARGET));
	assert_absent(&fixture.job().join(LOCAL_RECEIPT_LOCATION));
	let observed = inspect(fixture);
	assert_eq!(
		observed.disposition,
		RecoveryDisposition::RetainedPreparation
	);
	assert_eq!(observed.tail, JournalTail::Clean);
}

fn assert_short_resume(
	fixture: &Fixture,
	source: &Snapshot,
	source_metadata: &Metadata,
	stage: LinuxFileIdentity,
) {
	let complete = resume(&fixture.0, source_id()).expect("resume a full retained stage");
	assert_eq!(complete.disposition, RecoveryDisposition::Complete);
	assert_eq!(complete.tail, JournalTail::Clean);
	assert_absent(&stage_path(fixture));
	assert_eq!(Snapshot::read(&fixture.source()), *source, "source changed");
	let target = fixture.destination().join(TARGET);
	assert_source_metadata(
		fixture,
		&fs::metadata(&target).expect("stat published file"),
		source_metadata,
	);
	let published = Snapshot::read(&target);
	published.assert_copied_from(source);
	assert_eq!(
		published.identity, stage,
		"publish the original stage inode"
	);

	let frames = read_frames(
		fixture,
		&[PREPARATION_PREFIX, RESUMED_PREFIX, &SUCCESS_ORDER[2..]].concat(),
	);
	let started = assert_started(fixture, &frames, PREPARATION_PREFIX.len(), stage, 2);
	let intent = frames
		.iter()
		.find(|frame| frame.kind() == FrameKind::PublishIntent)
		.expect("record publication intent during resume");
	assert_intent(intent, started);
	assert_receipt_bound(fixture, &frames);
	let bytes = artifact(fixture, LOCAL_RECEIPT_LOCATION);
	let receipt = CopyReceipt::decode(&bytes).expect("decode the committed receipt");
	let evidence = receipt.evidence();
	assert_eq!(evidence.context.epoch, JournalEpoch::new(2));
	assert_eq!(evidence.source, source.identity);
	assert_eq!(evidence.target, component(TARGET));
	assert_eq!(evidence.stream.identity, stage);
	assert_eq!(evidence.stream.length.get(), source_metadata.len());
	assert_eq!(
		evidence.stream.digest.as_bytes(),
		blake3::hash(SOURCE_BYTES).as_bytes()
	);
	assert_stable_completion(fixture, complete);
}

fn journaled_access_time(fixture: &Fixture) -> SystemTime {
	let journal = File::open(fixture.job().join(SEGMENT)).expect("open the synthetic journal");
	let mut reader = FrameReader::new(journal, ChainHead::start());
	let _ = reader
		.next_frame()
		.expect("read job preparation")
		.expect("have job preparation");
	let entry = reader
		.next_frame()
		.expect("read entry preparation")
		.expect("have entry preparation");
	let atime = EntryPrepared::from_frame(&entry)
		.expect("decode source observation")
		.preparation()
		.source
		.times()
		.accessed_at;
	UNIX_EPOCH + Duration::new(u64::try_from(atime.seconds()).unwrap(), atime.nanoseconds())
}

fn assert_source_metadata(fixture: &Fixture, observed: &Metadata, source: &Metadata) {
	assert_eq!(observed.mode() & PERMISSION_BITS, SOURCE_MODE);
	assert_eq!(observed.mode(), source.mode(), "source mode");
	assert_eq!(
		(observed.uid(), observed.gid()),
		(source.uid(), source.gid())
	);
	assert_eq!(
		observed.accessed().unwrap(),
		journaled_access_time(fixture),
		"journaled atime",
	);
	assert_eq!(
		(observed.mtime(), observed.mtime_nsec()),
		(source.mtime(), source.mtime_nsec()),
		"journaled mtime",
	);
}
