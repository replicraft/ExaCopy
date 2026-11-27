use std::fs::{self, File};
use std::os::unix::fs::MetadataExt as _;

use exacopy_endpoint::UnixComponent;
use exacopy_model::{
	CopyBinding, CopyEffect, CopyEvent, CopySession, EntryId, JobId, PublishNoClobber, RunEpoch,
	StageId,
};
use rustix::io::Errno;

use super::{DirectoryBarriersError, PublishError, rename_error};
use crate::linux::{DestinationRoot, StageError};
use crate::scratch::Scratch;

#[test]
fn a_real_exclusive_rename_precedes_both_directory_barriers_even_on_failure() {
	const STAGE_DIR: &str = "directory-barrier-stage";
	const STAGE_FILE: &str = "directory-barrier-part";
	const TARGET: &str = "directory-barrier-target";
	const PAYLOAD: &[u8] = b"retain actual publication";
	let job = JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
		.expect("fixture job is UUIDv7");
	let scenarios = [
		(Ok(()), Ok(())),
		(Err(Errno::IO), Ok(())),
		(Ok(()), Err(Errno::NOSPC)),
		(Err(Errno::IO), Err(Errno::NOSPC)),
	];

	for (entry, (stage_sync, destination_sync)) in (1..).zip(scenarios) {
		let fixture = Scratch::new();
		let root_file = fixture.open();
		let root_id = directory_identity(&root_file);
		let root = DestinationRoot::from_directory(root_file).expect("managed root");
		let directory = root
			.create_stage_directory(component(STAGE_DIR))
			.expect("new stage directory");
		let stage_dir = fixture.path(STAGE_DIR);
		let stage_id = directory_identity(&File::open(&stage_dir).expect("open stage directory"));
		assert_ne!(stage_id, root_id);
		let binding = CopyBinding::new(
			job,
			EntryId::new(entry),
			RunEpoch::new(1),
			StageId::from_bytes([0x12; 16]),
		);
		let mut writer = directory
			.create_file(component(STAGE_FILE), component(TARGET), binding)
			.expect("new private stage");
		writer.write_all_at(0, PAYLOAD).expect("write payload");
		writer.flush().expect("flush payload");
		let stage = writer.close_writes().expect("release write access");
		let mut read_back = [0; PAYLOAD.len()];
		stage
			.read_exact_at(0, &mut read_back)
			.expect("verify read-back");
		assert_eq!(read_back, PAYLOAD);

		let mut calls = Vec::new();
		let target = fixture.path(TARGET);
		let original = stage_dir.join(STAGE_FILE);
		let result = stage.publish_with_barriers(authorization(binding), |directory| {
			assert_eq!(
				fs::read(&target).expect("rename precedes every barrier"),
				PAYLOAD
			);
			assert!(!original.exists(), "rename consumes only the staged name");
			let identity = directory_identity(directory);
			calls.push(identity);
			match identity {
				id if id == stage_id => stage_sync,
				id if id == root_id => destination_sync,
				_ => panic!("barrier opened an unrelated directory"),
			}
		});

		assert_eq!(calls, [stage_id, root_id]);
		if let Err(error) = &result {
			fixture.assert_debug_redacts(error, &[STAGE_DIR, STAGE_FILE, TARGET]);
		}
		match (stage_sync, destination_sync, result) {
			(Ok(()), Ok(()), Ok(())) => {}
			(
				Err(expected),
				Ok(()),
				Err(PublishError::BarriersFailed(DirectoryBarriersError::Stage(error))),
			) => {
				assert_eq!(error.raw_os_error(), Some(expected.raw_os_error()));
			}
			(
				Ok(()),
				Err(expected),
				Err(PublishError::BarriersFailed(DirectoryBarriersError::Destination(error))),
			) => {
				assert_eq!(error.raw_os_error(), Some(expected.raw_os_error()));
			}
			(
				Err(expected_stage),
				Err(expected_destination),
				Err(PublishError::BarriersFailed(DirectoryBarriersError::Both {
					stage,
					destination,
				})),
			) => {
				assert_eq!(stage.raw_os_error(), Some(expected_stage.raw_os_error()));
				assert_eq!(
					destination.raw_os_error(),
					Some(expected_destination.raw_os_error())
				);
			}
			(_, _, unexpected) => panic!("wrong barrier outcome: {unexpected:?}"),
		}
		assert_eq!(
			fs::read(&target).expect("retain the published file"),
			PAYLOAD
		);
		assert!(!original.exists(), "never move the published file back");
	}
}

#[test]
fn rename_errno_distinguishes_conflict_unsupported_and_reconciliation() {
	assert!(matches!(rename_error(Errno::EXIST), PublishError::Conflict));
	for errno in [Errno::INVAL, Errno::NOSYS, Errno::OPNOTSUPP, Errno::XDEV] {
		assert!(matches!(
			rename_error(errno),
			PublishError::Unsupported(error) if error.raw_os_error() == Some(errno.raw_os_error())
		));
	}
	for errno in [Errno::IO, Errno::INTR, Errno::NOENT, Errno::ACCESS] {
		assert!(matches!(
			rename_error(errno),
			PublishError::Uncertain(error) if error.raw_os_error() == Some(errno.raw_os_error())
		));
	}
}

#[test]
fn a_changed_public_name_after_rename_requires_reconciliation() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("managed root");
	let directory = root
		.create_stage_directory(component("stage"))
		.expect("private stage directory");
	let job = JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
		.expect("fixture job is UUIDv7");
	let binding = CopyBinding::new(
		job,
		EntryId::new(1),
		RunEpoch::new(1),
		StageId::from_bytes([1; 16]),
	);
	let mut writer = directory
		.create_file(component("part"), component("target"), binding)
		.expect("new private stage");
	writer
		.write_all_at(0, b"published bytes")
		.expect("write stage");
	writer.flush().expect("flush stage");
	let stage = writer.close_writes().expect("release writer");
	let target = fixture.path("target");
	let displaced = fixture.path("displaced");
	let mut calls = 0;
	let result = stage.publish_with_barriers(authorization(binding), |_| {
		if calls == 0 {
			fs::rename(&target, &displaced).expect("simulate a target rebind");
			fs::write(&target, b"different inode").expect("new public inode");
		}
		calls += 1;
		Ok(())
	});
	assert_eq!(calls, 2);
	assert!(matches!(
		result,
		Err(PublishError::ObservationFailed(StageError::IdentityChanged))
	));
	assert_eq!(
		fs::read(target).expect("new public name remains"),
		b"different inode"
	);
	assert_eq!(
		fs::read(displaced).expect("published inode remains"),
		b"published bytes"
	);
}

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).expect("valid fixture component")
}

fn directory_identity(directory: &File) -> (u64, u64) {
	let metadata = directory.metadata().expect("check held directory identity");
	assert!(metadata.is_dir());
	(metadata.dev(), metadata.ino())
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
	// This injects an abstract intent observation for testing adapter barriers.
	let Ok(Some(CopyEffect::PublishNoClobber(effect))) =
		session.apply(binding, CopyEvent::PublishIntentRecorded)
	else {
		panic!("model refused the fixture publication");
	};
	effect
}

#[path = "../../../../tests/unit/linux/publication_stage.rs"]
mod publication_stage;
