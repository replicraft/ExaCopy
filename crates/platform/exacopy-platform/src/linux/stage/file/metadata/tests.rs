use std::fs::{self, File, Permissions};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use exacopy_endpoint::UnixComponent;
use exacopy_model::{
	CopyBinding, CopyEffect, CopyEvent, CopySession, EntryId, JobId, PublishNoClobber, RunEpoch,
	StageId,
};
use rustix::fs::{self as linux, Timespec, Timestamps, XattrFlags};

use super::{ClosedStage, SourceObservation, StageError};
use crate::linux::{DestinationRoot, ReadRoot, SourceTimestamp, StageDirectory};
use crate::scratch::Scratch;

const SOURCE: &str = "metadata-source";
const STAGE_DIR: &str = "metadata-stage";
const STAGE_FILE: &str = "metadata-part";
const TARGET: &str = "metadata-destination";
const PAYLOAD: &[u8] = b"retained content";
const META_TIMES: Timestamps = Timestamps {
	last_access: Timespec {
		tv_sec: 1_678_000_012,
		tv_nsec: 345_678_901,
	},
	last_modification: Timespec {
		tv_sec: 1_689_000_013,
		tv_nsec: 234_567_890,
	},
};

#[test]
fn verified_permissions_and_nanosecond_times_survive_publication() {
	let fixture = Scratch::new();
	let source = observed_source(&fixture, 0o440);
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination root");
	let directory = root
		.create_stage_directory(component(STAGE_DIR))
		.expect("private stage directory");
	let binding = binding();
	let read_back = stage(&directory, binding, PAYLOAD);
	let sealed = read_back
		.apply_metadata(source)
		.expect("apply exact required metadata");
	sealed.check_current().expect("post-metadata stage matches");
	sealed
		.publish_no_clobber(authorization(binding))
		.expect("publish the same inode");

	let target = fixture.path(TARGET);
	let attributes = fs::metadata(&target).expect("published metadata before any data reads");
	assert_eq!(attributes.mode() & 0o7777, 0o440);
	assert_eq!(attributes.uid(), source.owner());
	assert_eq!(attributes.gid(), source.group());
	assert_eq!(attributes.atime(), source.accessed_at().seconds());
	assert_eq!(
		attributes.atime_nsec(),
		i64::from(source.accessed_at().nanoseconds())
	);
	assert_eq!(attributes.mtime(), source.modified_at().seconds());
	assert_eq!(
		attributes.mtime_nsec(),
		i64::from(source.modified_at().nanoseconds())
	);
	assert_eq!(fs::read(target).expect("read published bytes"), PAYLOAD);
	assert!(fixture.path(STAGE_DIR).exists());
}

#[test]
fn metadata_can_preserve_a_previously_captured_access_time() {
	let fixture = Scratch::new();
	let source = observed_source(&fixture, 0o440);
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let directory = root.create_stage_directory(component(STAGE_DIR)).unwrap();
	let accessed_at = SourceTimestamp::new(1_671_000_004, 123_456_789).unwrap();
	assert!(SourceTimestamp::new(1_671_000_004, 1_000_000_000).is_err());
	let binding = binding();
	let sealed = stage(&directory, binding, PAYLOAD)
		.apply_metadata_with_access_time(source, accessed_at)
		.unwrap();
	sealed.publish_no_clobber(authorization(binding)).unwrap();

	let attributes = fs::metadata(fixture.path(TARGET)).unwrap();
	assert_eq!(attributes.mode() & 0o7777, source.mode());
	assert_eq!(attributes.uid(), source.owner());
	assert_eq!(attributes.gid(), source.group());
	assert_eq!(attributes.atime(), accessed_at.seconds());
	assert_eq!(
		attributes.atime_nsec(),
		i64::from(accessed_at.nanoseconds())
	);
	assert_eq!(attributes.mtime(), source.modified_at().seconds());
	assert_eq!(
		attributes.mtime_nsec(),
		i64::from(source.modified_at().nanoseconds())
	);
}

#[test]
fn unsupported_special_mode_and_wrong_length_leave_private_evidence() {
	for (mode, contents) in [(0o4600, PAYLOAD), (0o600, b"short".as_slice())] {
		let fixture = Scratch::new();
		let source = observed_source(&fixture, mode);
		let root = DestinationRoot::from_directory(fixture.open()).expect("held destination root");
		let directory = root
			.create_stage_directory(component(STAGE_DIR))
			.expect("private stage directory");
		let result = stage(&directory, binding(), contents).apply_metadata(source);
		if contents == PAYLOAD {
			assert!(matches!(result, Err(StageError::UnsupportedMode)));
		} else {
			assert!(matches!(result, Err(StageError::MetadataMismatch)));
		}
		let private = fixture.path(STAGE_DIR).join(STAGE_FILE);
		assert_eq!(
			fs::metadata(&private).expect("stage metadata").mode() & 0o7777,
			0o600
		);
		assert_eq!(
			fs::read(private).expect("retain the rejected stage"),
			contents
		);
		assert!(!fixture.path(TARGET).exists());
	}
}

#[test]
fn stage_with_visible_extended_attributes_cannot_apply_required_metadata() {
	let fixture = Scratch::new();
	let source = observed_source(&fixture, 0o440);
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination root");
	let directory = root
		.create_stage_directory(component(STAGE_DIR))
		.expect("private stage directory");
	let binding = binding();
	let mut writer = directory
		.create_file(component(STAGE_FILE), component(TARGET), binding)
		.expect("exclusive stage");
	writer.write_all_at(0, PAYLOAD).expect("write stage");
	let private = fixture.path(STAGE_DIR).join(STAGE_FILE);
	let staged_inode = File::open(&private).expect("open synthetic stage fixture");
	linux::fsetxattr(
		&staged_inode,
		c"user.synthetic",
		b"required",
		XattrFlags::CREATE,
	)
	.expect("install visible synthetic attribute");
	writer.flush().expect("flush stage");
	let stage = writer.close_writes().expect("close the stage writer");

	assert!(matches!(
		stage.apply_metadata(source),
		Err(StageError::UnexpectedExtendedAttributes)
	));
	assert_eq!(
		fs::metadata(&private).expect("retained stage").mode() & 0o7777,
		0o600
	);
	assert!(!fixture.path(TARGET).exists());
}

pub(super) fn observed_source(fixture: &Scratch, mode: u32) -> SourceObservation {
	let path = fixture.path(SOURCE);
	fs::write(&path, PAYLOAD).expect("seed the source fixture");
	let file = File::open(&path).expect("hold the source fixture");
	file.set_permissions(Permissions::from_mode(mode))
		.expect("fixture permissions");
	linux::futimens(&file, &META_TIMES).expect("fixture nanosecond timestamps");

	let root = ReadRoot::from_directory(fixture.open()).expect("bind fixture source root");
	let source = root
		.open_regular(component(SOURCE))
		.expect("read-only fixture source");
	source.observation()
}

fn stage<'a>(
	directory: &'a StageDirectory<'_>,
	binding: CopyBinding,
	contents: &[u8],
) -> ClosedStage<'a> {
	let mut writer = directory
		.create_file(component(STAGE_FILE), component(TARGET), binding)
		.expect("exclusive stage");
	let original = writer.identity();
	writer.write_all_at(0, contents).expect("write stage");
	writer.flush().expect("flush stage");
	let stage = writer.close_writes().expect("close data writes");
	assert_eq!(stage.identity(), original);
	let mut read_back = vec![0; contents.len()];
	stage
		.read_exact_at(0, &mut read_back)
		.expect("independently read stage");
	assert_eq!(read_back, contents);
	stage
}

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).expect("valid fixture component")
}

pub(super) fn binding() -> CopyBinding {
	let job = JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
		.expect("synthetic UUIDv7");
	CopyBinding::new(
		job,
		EntryId::new(1),
		RunEpoch::new(1),
		StageId::from_bytes([0x27; 16]),
	)
}

pub(super) fn authorization(binding: CopyBinding) -> PublishNoClobber {
	let mut session = CopySession::new(binding);
	for event in [
		CopyEvent::StagePrepared,
		CopyEvent::WritersJoined,
		CopyEvent::DataFlushed,
		CopyEvent::ReadbackVerified,
		CopyEvent::MetadataReady,
		CopyEvent::StageSealed,
	] {
		let _ = session.apply(binding, event).expect("fixture observation");
	}
	// This fixture exercises metadata and actual rename, not persistence of the intent record.
	let Ok(Some(CopyEffect::PublishNoClobber(token))) =
		session.apply(binding, CopyEvent::PublishIntentRecorded)
	else {
		panic!("model did not authorize the fixture")
	};
	token
}
