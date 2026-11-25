use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, symlink};

use exacopy_endpoint::UnixComponent;
use exacopy_model::{
	CopyBinding, CopyEffect, CopyEvent, CopySession, EntryId, JobId, PublishNoClobber, RunEpoch,
	StageId,
};

use super::{DestinationRoot, TargetStatus};
use crate::linux::{ReadRoot, StageError};
use crate::scratch::Scratch;

const JOB: &str = "privately-owned-job";
const RECORD: &str = "owner.cbor";
const STAGE: &str = "stage";
const JOURNAL: &str = "journal";
const SEGMENT: &str = "00000000000000000001.exajnl";
const PART: &str = "private-payload";
const TARGET: &str = "target";
const DATA: &[u8] = b"one file through the nested stage";

#[test]
fn fixed_owner_and_journal_records_can_only_be_created_exclusively() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination");
	let job = root
		.create_job_directory(component(JOB))
		.expect("private job");
	let stage = job.create_stage_directory().expect("fixed stage directory");
	let journal = job
		.create_journal_directory()
		.expect("fixed journal directory");
	let mut owner = job.create_owner_record().expect("new owner record");
	let mut segment = journal.create_first_segment().expect("new journal segment");
	owner
		.write_all(b"fixture owner")
		.expect("write private manifest");
	segment
		.write_all(b"fixture segment")
		.expect("write private segment");
	owner.sync_all().expect("owner record barrier");
	segment.sync_all().expect("segment barrier");
	stage.sync_directory().expect("stage directory barrier");
	journal.sync_directory().expect("journal directory barrier");
	job.sync_directory().expect("job directory barrier");
	root.sync_directory()
		.expect("destination directory barrier");

	let job_path = fixture.path(JOB);
	let journal_path = job_path.join(JOURNAL);
	for (identity, path) in [
		(job.identity(), job_path.clone()),
		(stage.identity(), job_path.join(STAGE)),
		(journal.identity(), journal_path.clone()),
	] {
		let metadata = fs::metadata(path).expect("private directory metadata");
		assert_eq!(metadata.mode() & 0o7777, 0o700);
		assert_eq!(metadata.dev(), identity.device());
		assert_eq!(metadata.ino(), identity.inode());
	}
	for file in [&owner, &segment] {
		let metadata = file.metadata().expect("private record metadata");
		assert_eq!(metadata.mode() & 0o7777, 0o600);
		assert_eq!(metadata.nlink(), 1);
	}
	assert!(matches!(
		root.create_job_directory(component(JOB)),
		Err(StageError::AlreadyExists)
	));
	assert!(matches!(
		job.create_stage_directory(),
		Err(StageError::AlreadyExists)
	));
	assert!(matches!(
		job.create_journal_directory(),
		Err(StageError::AlreadyExists)
	));
	assert!(matches!(
		job.create_owner_record(),
		Err(StageError::AlreadyExists)
	));
	assert!(matches!(
		journal.create_first_segment(),
		Err(StageError::AlreadyExists)
	));
	assert_eq!(
		fs::read(job_path.join(RECORD)).expect("retain owner record"),
		b"fixture owner"
	);
	assert_eq!(
		fs::read(journal_path.join(SEGMENT)).expect("retain segment"),
		b"fixture segment"
	);
	assert!(!fixture.path(RECORD).exists());
	assert!(!fixture.path(SEGMENT).exists());
	fixture.assert_debug_redacts(&job, &[JOB]);
	fixture.assert_debug_redacts(&journal, &[JOB, JOURNAL]);
}

#[test]
fn rebind_of_the_job_or_either_child_blocks_new_effects() {
	for displaced in [JOB, JOURNAL, STAGE] {
		let fixture = Scratch::new();
		let root = DestinationRoot::from_directory(fixture.open()).expect("held destination");
		let job = root
			.create_job_directory(component(JOB))
			.expect("private job");
		let journal = job.create_journal_directory().expect("fixed journal");
		let stage = job.create_stage_directory().expect("fixed stage");
		let mut writer = stage
			.create_file(component(PART), component(TARGET), binding())
			.expect("owned stage");
		writer.write_all_at(0, DATA).expect("fill stage");
		writer.flush().expect("flush stage");
		let closed = writer.close_writes().expect("close writes");
		let moved = fixture.path("displaced");
		let original = if displaced == JOB {
			fixture.path(JOB)
		} else {
			fixture.path(JOB).join(displaced)
		};
		fs::rename(&original, &moved).expect("rebind simulated same-principal namespace");
		if displaced == JOB {
			let replacement = root
				.create_job_directory(component(JOB))
				.expect("replacement job");
			let _ = replacement
				.create_stage_directory()
				.expect("replacement stage");
			let _ = replacement
				.create_journal_directory()
				.expect("replacement journal");
			assert!(matches!(
				job.sync_directory(),
				Err(StageError::IdentityChanged)
			));
			assert!(matches!(
				job.create_owner_record(),
				Err(StageError::IdentityChanged)
			));
		} else if displaced == JOURNAL {
			let _ = job.create_journal_directory().expect("replacement journal");
		} else {
			let _ = job.create_stage_directory().expect("replacement stage");
		}
		if displaced == JOB || displaced == JOURNAL {
			assert!(matches!(
				journal.sync_directory(),
				Err(StageError::IdentityChanged)
			));
			assert!(matches!(
				journal.create_first_segment(),
				Err(StageError::IdentityChanged)
			));
		}
		if displaced == JOB || displaced == STAGE {
			assert!(matches!(
				stage.sync_directory(),
				Err(StageError::IdentityChanged)
			));
			assert!(matches!(
				closed.publish_no_clobber(authorization(binding())),
				Err(crate::linux::PublishError::StageChanged(
					StageError::IdentityChanged
				))
			));
			assert!(!fixture.path(TARGET).exists());
		}
	}
}

#[test]
fn nested_stage_publishes_to_original_destination_parent() {
	let fixture = Scratch::new();
	fs::write(fixture.path("source"), DATA).expect("seed source");
	let reader = ReadRoot::from_directory(fixture.open()).expect("held source root");
	let source = reader
		.open_regular(component("source"))
		.expect("source capability");
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination");
	let job = root
		.create_job_directory(component(JOB))
		.expect("private job");
	let stage = job.create_stage_directory().expect("fixed stage");
	let mut writer = stage
		.create_file(component(PART), component(TARGET), binding())
		.expect("owned stage");
	writer
		.check_ownership(source.observation())
		.expect("source ownership fits stage");
	writer.write_all_at(0, DATA).expect("write fixture");
	writer.flush().expect("flush fixture");
	let closed = writer.close_writes().expect("read-only stage");
	let mut read_back = [0; DATA.len()];
	closed
		.read_exact_at(0, &mut read_back)
		.expect("read back stage");
	assert_eq!(read_back, DATA);
	let sealed = closed
		.apply_metadata(source.observation())
		.expect("verify required metadata");
	sealed
		.publish_no_clobber(authorization(binding()))
		.expect("publish nested stage");
	assert_eq!(fs::read(fixture.path(TARGET)).expect("public target"), DATA);
	assert!(!fixture.path(JOB).join(TARGET).exists());
	assert!(!fixture.path(JOB).join(STAGE).join(PART).exists());
}

#[test]
fn preflight_occupancy_never_follows_symlinks_or_mutates_incumbents() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination");
	fs::write(fixture.path("incumbent"), b"retain").expect("seed incumbent");
	fs::create_dir(fixture.path("directory")).expect("seed directory");
	symlink("missing", fixture.path("dangling")).expect("seed dangling symlink");
	assert_eq!(
		root.target_status(component("absent"))
			.expect("check absent name"),
		TargetStatus::Absent
	);
	for incumbent in ["incumbent", "directory", "dangling"] {
		assert_eq!(
			root.target_status(component(incumbent))
				.expect("check incumbent"),
			TargetStatus::Occupied
		);
	}
	assert_eq!(
		fs::read(fixture.path("incumbent")).expect("retain incumbent"),
		b"retain"
	);
	assert!(fixture.path("dangling").is_symlink());
}

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).expect("fixture component")
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
			.expect("fixture model observation");
	}
	// Simulate an accepted intent to exercise the real adapter boundary.
	let Ok(Some(CopyEffect::PublishNoClobber(authorization))) =
		session.apply(binding, CopyEvent::PublishIntentRecorded)
	else {
		panic!("model rejected fixture")
	};
	authorization
}
