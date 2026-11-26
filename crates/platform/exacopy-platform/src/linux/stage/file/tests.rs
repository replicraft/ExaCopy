use std::fs;

use exacopy_endpoint::UnixComponent;
use exacopy_model::{CopyBinding, EntryId, JobId, RunEpoch, StageId};
use rustix::io::Errno;

use crate::linux::{DestinationRoot, StageError};
use crate::scratch::Scratch;

#[test]
fn a_failed_file_barrier_permanently_revokes_the_stage() {
	const STAGE_DIR: &str = "synchronization-stage";
	const STAGE_FILE: &str = "synchronization-part";
	const TARGET: &str = "synchronization-target";
	const PAYLOAD: &[u8] = b"retain the data for reconciliation";
	let job = JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
		.expect("fixture job is UUIDv7");

	for (attempt, failure) in [(1, Errno::IO), (2, Errno::NOSPC), (3, Errno::INTR)] {
		let fixture = Scratch::new();
		let root = DestinationRoot::from_directory(fixture.open()).expect("managed root");
		let directory = root
			.create_stage_directory(component(STAGE_DIR))
			.expect("fresh stage directory");
		let binding = CopyBinding::new(
			job,
			EntryId::new(attempt),
			RunEpoch::new(1),
			StageId::from_bytes([0x13; 16]),
		);
		let mut stage = directory
			.create_file(component(STAGE_FILE), component(TARGET), binding)
			.expect("fresh stage file");
		stage.write_all_at(0, PAYLOAD).expect("initial write");

		let result = stage.flush_with(|_| Err(failure));
		assert!(matches!(
			result,
			Err(StageError::BarrierFailed(source))
				if source.raw_os_error() == Some(failure.raw_os_error())
		));

		let mut retry_count = 0;
		let retry = stage.flush_with(|_| {
			retry_count += 1;
			Ok(())
		});
		assert!(matches!(retry, Err(StageError::PriorBarrierFailure)));
		assert_eq!(retry_count, 0, "no retry may reach the file barrier");
		assert!(matches!(
			stage.flush(),
			Err(StageError::PriorBarrierFailure)
		));
		assert!(matches!(
			stage.write_all_at(0, b"replacement"),
			Err(StageError::PriorBarrierFailure)
		));
		assert!(matches!(
			stage.set_len(0),
			Err(StageError::PriorBarrierFailure)
		));
		fixture.assert_debug_redacts(&stage, &[STAGE_DIR, STAGE_FILE, TARGET]);
		assert!(matches!(
			stage.close_writes(),
			Err(StageError::PriorBarrierFailure)
		));
		assert_eq!(
			fs::read(fixture.path(STAGE_DIR).join(STAGE_FILE)).expect("retain the private file"),
			PAYLOAD
		);
		assert!(!fixture.path(TARGET).exists());
	}
}

#[test]
fn a_prefix_barrier_requires_matching_lengths_and_preserves_a_failed_writeback() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let directory = root.create_stage_directory(component("prefix")).unwrap();
	let job =
		JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]).unwrap();
	let binding = CopyBinding::new(
		job,
		EntryId::new(1),
		RunEpoch::new(1),
		StageId::from_bytes([1; 16]),
	);
	let mut stage = directory
		.create_file(component("part"), component("target"), binding)
		.unwrap();
	assert_eq!(stage.sync_prefix(0).unwrap(), stage.identity());
	stage.write_all_at(0, b"prefix").unwrap();
	let mut sync_called = false;
	assert!(matches!(
		stage.sync_prefix_with(2, |_| {
			sync_called = true;
			Ok(())
		}),
		Err(StageError::IdentityChanged)
	));
	assert!(!sync_called);
	assert_eq!(stage.sync_prefix(6).unwrap(), stage.identity());

	assert!(matches!(
		stage.sync_prefix_with(6, |_| Err(Errno::IO)),
		Err(StageError::BarrierFailed(_))
	));
	assert!(matches!(
		stage.observe_prefix(6),
		Err(StageError::PriorBarrierFailure)
	));
	assert!(matches!(
		stage.sync_prefix(6),
		Err(StageError::PriorBarrierFailure)
	));
	assert!(matches!(
		stage.close_writes(),
		Err(StageError::PriorBarrierFailure)
	));
	assert_eq!(
		fs::read(fixture.path("prefix").join("part")).unwrap(),
		b"prefix"
	);
}

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).expect("valid fixture component")
}

#[test]
fn guarded_prefix_refuses_before_sync_and_never_uses_authority_for_invalid_extent() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let directory = root.create_stage_directory(component("prefix")).unwrap();
	let job =
		JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]).unwrap();
	let binding = CopyBinding::new(
		job,
		EntryId::new(1),
		RunEpoch::new(1),
		StageId::from_bytes([1; 16]),
	);
	let mut stage = directory
		.create_file(component("part"), component("target"), binding)
		.unwrap();
	stage.write_all_at(0, b"prefix").unwrap();
	assert!(matches!(
		stage.sync_prefix_admitted(2, || -> std::io::Result<()> {
			panic!("invalid extent must fail before admission")
		}),
		Err(StageError::IdentityChanged)
	));
	assert!(matches!(
		stage.flush_admitted_with(
			|| Err::<(), _>(std::io::Error::other("expired after the named observation")),
			|_| panic!("refused authority must not start fsync"),
		),
		Err(StageError::Admission(_))
	));
	assert!(matches!(stage.close_writes(), Err(StageError::Unflushed)));
	assert_eq!(
		fs::read(fixture.path("prefix").join("part")).unwrap(),
		b"prefix"
	);
	assert!(!fixture.path("target").exists());
}
