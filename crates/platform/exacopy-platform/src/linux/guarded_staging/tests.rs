use std::cell::{Cell, RefCell};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt as _;

use exacopy_endpoint::linux_apply::{ApplyRole, ApplyStep, LocalApplyAdmission};

use super::{GuardedStageDirectory, GuardedStageReader, GuardedStageWriter};
use crate::linux::{DestinationRoot, ReadRoot, StageError};
use crate::scratch::Scratch;

/// Records the real entry points of a temporary native fixture. This is not an issuer.
#[derive(Default)]
pub(in crate::linux) struct FixtureAdmission {
	pub(in crate::linux) refuse: Cell<Option<ApplyStep>>,
	pub(in crate::linux) steps: RefCell<Vec<ApplyStep>>,
}

impl LocalApplyAdmission for FixtureAdmission {
	type Guard<'gate> = ();

	fn enter(&self, step: ApplyStep) -> io::Result<()> {
		self.steps.borrow_mut().push(step);
		if self.refuse.get() == Some(step) {
			return Err(io::Error::other("fixture denied effect"));
		}
		Ok(())
	}
}

#[test]
fn guarded_stage_checks_refusal_before_native_writes_and_each_metadata_mutation() {
	use exacopy_model::{CopyBinding, EntryId, JobId, RunEpoch, StageId};
	use rustix::fs::{self as linux, Timespec, Timestamps};
	use std::os::unix::fs::PermissionsExt as _;

	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let source_root = ReadRoot::from_directory(fixture.open()).unwrap();
	let source_path = fixture.path("source");
	fs::write(&source_path, b"payload").unwrap();
	fs::set_permissions(&source_path, fs::Permissions::from_mode(0o440)).unwrap();
	let source_file = fs::File::open(&source_path).unwrap();
	let times = Timestamps {
		last_access: Timespec {
			tv_sec: 1_600_000_000,
			tv_nsec: 321,
		},
		last_modification: Timespec {
			tv_sec: 1_600_000_001,
			tv_nsec: 123,
		},
	};
	linux::futimens(&source_file, &times).unwrap();
	let source = source_root
		.open_regular(component(b"source"))
		.unwrap()
		.observation();
	let job = root.create_job_directory(component(b"job")).unwrap();
	let directory = job.create_stage_directory().unwrap();
	let binding = CopyBinding::new(
		JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]).unwrap(),
		EntryId::new(1),
		RunEpoch::new(1),
		StageId::from_bytes([1; 16]),
	);
	let gate = FixtureAdmission::default();
	let create = ApplyStep::Create(ApplyRole::Stage);
	let write = ApplyStep::Write(ApplyRole::Stage, 0, 7);
	gate.refuse.set(Some(create));
	assert!(matches!(
		GuardedStageDirectory::create_file_admitted(
			&directory,
			component(b"part"),
			component(b"target"),
			binding,
			&gate
		),
		Err(StageError::Admission(_))
	));
	let part = fixture.path("job/stage/part");
	assert!(!part.exists());
	gate.refuse.set(Some(write));
	let mut writer = GuardedStageDirectory::create_file_admitted(
		&directory,
		component(b"part"),
		component(b"target"),
		binding,
		&gate,
	)
	.unwrap();
	assert!(matches!(
		writer.write_window_admitted(0, b"payload", &gate),
		Err(StageError::Admission(_))
	));
	assert_eq!(fs::metadata(&part).unwrap().len(), 0);
	gate.refuse.set(None);
	writer.write_window_admitted(0, b"payload", &gate).unwrap();
	let extent = ApplyStep::SetStageExtent(0);
	gate.refuse.set(Some(extent));
	assert!(matches!(
		writer.set_len_admitted(0, &gate),
		Err(StageError::Admission(_))
	));
	assert_eq!(fs::metadata(&part).unwrap().len(), 7);
	gate.refuse.set(None);
	writer.set_len_admitted(7, &gate).unwrap();
	writer.flush_stage_admitted(&gate).unwrap();
	let stage = writer.close_writes().unwrap();
	let before = fs::metadata(&part).unwrap();
	gate.refuse.set(Some(ApplyStep::SetStageTimes));
	assert!(matches!(
		stage.apply_metadata_admitted(source, source.accessed_at(), &gate),
		Err(StageError::Admission(_))
	));
	let after = fs::metadata(&part).unwrap();
	assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
	assert_eq!(
		after.mode() & 0o777,
		0o440,
		"the admitted chmod remains in evidence"
	);
	assert_eq!(
		(after.mtime(), after.mtime_nsec()),
		(before.mtime(), before.mtime_nsec())
	);
	assert_eq!(fs::read(&part).unwrap(), b"payload");
	assert!(!fixture.path("target").exists());
	assert_eq!(
		gate.steps.into_inner(),
		[
			create,
			create,
			write,
			write,
			extent,
			ApplyStep::SetStageExtent(7),
			ApplyStep::Sync(ApplyRole::Stage),
			ApplyStep::SetStagePermissions,
			ApplyStep::SetStageTimes,
		],
	);
}

fn component(name: &[u8]) -> exacopy_endpoint::UnixComponent<'_> {
	exacopy_endpoint::UnixComponent::new(name).unwrap()
}
