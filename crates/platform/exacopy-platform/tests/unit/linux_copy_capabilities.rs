use std::fs::{self, File, FileTimes, Metadata};
use std::os::unix::fs::MetadataExt as _;
use std::time::{Duration, UNIX_EPOCH};

use exacopy_endpoint::linux_copy::{
	CheckpointPages, CopyDestinationView, CopySource, CopySourceRoot, CopyWorkspace,
	PublishableStageDirectory, TargetObservation,
};
use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::{ReadView, UnixComponent};
use exacopy_model::{
	CopyBinding, CopyEffect, CopyEvent, CopySession, EntryId, JobId, PublishNoClobber, RunEpoch,
	StageId,
};

use crate::linux::{DestinationRoot, ReadError, ReadRoot, StageError};
use crate::scratch::Scratch;

#[test]
fn copy_source_reports_held_metadata_and_reads_only_the_requested_range() {
	let fixture = Scratch::new();
	let path = fixture.path("source");
	let payload = b"abcdef";
	fs::write(&path, payload).expect("seed source fixture");
	fs::hard_link(&path, fixture.path("same-inode")).expect("link fixture source");
	let times = FileTimes::new()
		.set_accessed(UNIX_EPOCH + Duration::new(1_600_000_000, 123_000_000))
		.set_modified(UNIX_EPOCH + Duration::new(1_700_000_000, 456_000_000));
	File::open(&path)
		.expect("open fixture for timestamp setup")
		.set_times(times)
		.expect("set distinguishable source timestamps");
	let expected = fs::metadata(&path).expect("observe source inode independently");
	let directory = fixture.open();
	let expected_root = directory.metadata().expect("observe source directory");
	let root = ReadRoot::from_directory(directory).expect("hold source root");
	assert_eq!(CopySourceRoot::identity(&root), identity(&expected_root));
	let source = CopySourceRoot::open_regular(&root, component("source"))
		.expect("open source using the copy capability");
	assert_eq!(
		JobFileIdentity::from(source.identity()),
		identity(&expected)
	);
	let captured = source.copy_observation();
	assert_eq!(captured.mode, expected.mode() & 0o7777);
	assert_eq!(captured.owner, expected.uid());
	assert_eq!(captured.group, expected.gid());
	assert_eq!(captured.links, expected.nlink());
	for (captured, seconds, nanoseconds) in [
		(
			captured.accessed_at,
			expected.atime(),
			expected.atime_nsec(),
		),
		(
			captured.modified_at,
			expected.mtime(),
			expected.mtime_nsec(),
		),
		(captured.changed_at, expected.ctime(), expected.ctime_nsec()),
	] {
		assert_eq!(captured.seconds, seconds);
		assert_eq!(i64::from(captured.nanoseconds), nanoseconds);
	}

	let mut range = [0; 3];
	ReadView::read_exact_at(&source, 2, &mut range).expect("read interior source range");
	assert_eq!(&range, b"cde");
	let mut beyond_end = [0x5a; 2];
	assert!(matches!(
		ReadView::read_exact_at(&source, 5, &mut beyond_end),
		Err(ReadError::RangeOutsideFile)
	));
	assert_eq!(beyond_end, [0x5a; 2]);
	assert_eq!(source.copy_observation(), captured);
	assert_eq!(fs::read(path).expect("read retained source"), payload);
}

#[test]
fn copy_workspace_publishes_the_verified_stage_as_the_fresh_target() {
	const PAYLOAD: &[u8] = b"staged copy";
	let fixture = Scratch::new();
	let source_path = fixture.path("source");
	let target_path = fixture.path("target");
	fs::write(&source_path, PAYLOAD).expect("seed source fixture");
	let original_source = fs::metadata(&source_path).expect("observe source inode");
	let source_root = ReadRoot::from_directory(fixture.open()).expect("hold source root");
	let source = CopySourceRoot::open_regular(&source_root, component("source"))
		.expect("hold source fixture");
	let directory = fixture.open();
	let expected_root = directory.metadata().expect("observe destination directory");
	let root = DestinationRoot::from_directory(directory).expect("hold destination root");
	assert_eq!(
		CopyDestinationView::identity(&root),
		identity(&expected_root)
	);
	let target = component("target");
	assert_eq!(
		root.observe_target(target).expect("observe initial target"),
		TargetObservation::Absent
	);

	let job = root
		.create_job_directory(component("job"))
		.expect("create private job");
	let stage = CopyWorkspace::create_stage_directory(&job).expect("create private stage");
	let stage_path = fixture.path("job").join("stage");
	let stage_metadata = fs::metadata(&stage_path).expect("observe stage directory");
	assert_eq!(
		PublishableStageDirectory::identity(&stage),
		identity(&stage_metadata)
	);
	assert!(matches!(
		CopyWorkspace::create_stage_directory(&job),
		Err(StageError::AlreadyExists)
	));

	let binding = binding();
	let mut writer = stage
		.create_file(component("payload"), target, binding)
		.expect("allocate staged fixture");
	writer
		.check_ownership(source.observation())
		.expect("confirm ownership");
	let mut contents = [0; PAYLOAD.len()];
	ReadView::read_exact_at(&source, 0, &mut contents).expect("read source payload");
	writer
		.write_all_at(0, &contents)
		.expect("write private payload");
	writer.flush().expect("flush private payload");
	let closed = writer.close_writes().expect("release data-write authority");
	let mut read_back = [0; PAYLOAD.len()];
	closed
		.read_exact_at(0, &mut read_back)
		.expect("read staged bytes");
	assert_eq!(&read_back, PAYLOAD);
	let sealed = closed
		.apply_metadata(source.observation())
		.expect("apply and check required metadata");
	let private_path = stage_path.join("payload");
	let staged = fs::metadata(&private_path).expect("observe verified stage");

	stage
		.publish(sealed, authorization(binding))
		.expect("publish verified stage exclusively");
	assert_eq!(
		root.observe_target(target)
			.expect("observe published target"),
		TargetObservation::Occupied
	);
	assert_eq!(
		fs::read(&target_path).expect("read published target"),
		PAYLOAD
	);
	assert_eq!(
		identity(&fs::metadata(target_path).expect("observe published state")),
		identity(&staged)
	);
	let private_lookup = fs::symlink_metadata(private_path);
	assert!(matches!(
		private_lookup,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound
	));
	assert_eq!(
		fs::read(&source_path).expect("read retained source"),
		PAYLOAD
	);
	let retained = fs::metadata(source_path).expect("observe retained source inode");
	assert_eq!(identity(&retained), identity(&original_source));
	assert_eq!(retained.mode(), original_source.mode());
	assert_eq!(
		retained.modified().expect("retained source mtime"),
		original_source.modified().expect("original source mtime")
	);
	assert_eq!(retained.ctime(), original_source.ctime());
	assert_eq!(retained.ctime_nsec(), original_source.ctime_nsec());
}

#[test]
fn checkpoint_capability_preserves_an_existing_page_and_its_identity() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("hold destination root");
	let job = root
		.create_job_directory(component("job"))
		.expect("create private job");
	let checkpoints =
		CopyWorkspace::create_checkpoint_directory(&job).expect("create checkpoint directory");
	assert!(matches!(
		CopyWorkspace::create_checkpoint_directory(&job),
		Err(StageError::AlreadyExists)
	));
	let original = b"checkpoint fixture";
	checkpoints
		.persist_page(1, original)
		.expect("persist first page");
	let page = fixture
		.path("job")
		.join("checkpoints")
		.join("range-0000000001.cbor");
	let saved = fs::metadata(&page).expect("observe checkpoint file identity");
	assert!(matches!(
		checkpoints.persist_page(1, b"replacement"),
		Err(StageError::AlreadyExists)
	));
	assert_eq!(fs::read(&page).expect("read retained checkpoint"), original);
	assert_eq!(
		identity(&fs::metadata(page).expect("checkpoint still exists")),
		identity(&saved)
	);
}

fn identity(metadata: &Metadata) -> JobFileIdentity {
	JobFileIdentity {
		device: metadata.dev(),
		inode: metadata.ino(),
	}
}

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).expect("validate fixture name")
}

fn binding() -> CopyBinding {
	let job = JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
		.expect("fixture UUIDv7");
	CopyBinding::new(
		job,
		EntryId::new(1),
		RunEpoch::new(1),
		StageId::from_bytes([0x23; 16]),
	)
}

fn authorization(binding: CopyBinding) -> PublishNoClobber {
	let mut session = CopySession::new(binding);
	for event in [
		CopyEvent::StagePrepared,
		CopyEvent::WritersJoined,
		CopyEvent::DataFlushed,
		CopyEvent::ReadbackVerified,
		CopyEvent::MetadataReady,
		CopyEvent::StageSealed,
	] {
		let _ = session
			.apply(binding, event)
			.expect("record fixture observation");
	}
	// The adapter fixture simulates the coordinator's accepted intent record.
	let Ok(Some(CopyEffect::PublishNoClobber(permit))) =
		session.apply(binding, CopyEvent::PublishIntentRecorded)
	else {
		panic!("model rejected fixture publication")
	};
	permit
}
