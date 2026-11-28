use std::cell::{Cell, RefCell};
use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, symlink};
use std::path::Path;

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_apply::{
	ApplyRole, ApplyStep, GuardedCheckpointPages, LocalApplyAdmission,
};

use crate::linux::{DestinationRoot, StageError};
use crate::scratch::Scratch;

const JOB: &str = "private-job";
const CHECKPOINTS: &str = "checkpoints";
const FIRST_PAGE: &str = "range-0000000001.cbor";
const LAST_ORDINAL: u32 = 4_096;
const MAX_LENGTH: usize = 95;
const DATA: [u8; MAX_LENGTH] = [0xa7; MAX_LENGTH];

#[test]
fn page_creation_is_exclusive_and_checked_recovery_reads_the_original() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination");
	let job = root.create_job_directory(job_name()).expect("private job");
	let checkpoints = job
		.create_checkpoint_directory()
		.expect("private checkpoints");
	job.sync_directory()
		.expect("persist checkpoint directory name");
	assert!(matches!(
		job.create_checkpoint_directory(),
		Err(StageError::AlreadyExists)
	));
	checkpoints
		.write_page(1, &DATA)
		.expect("persist checkpoint page");
	checkpoints
		.write_page(LAST_ORDINAL, &[0x55])
		.expect("persist last allowed checkpoint page");
	assert!(matches!(
		checkpoints.write_page(1, &[0]),
		Err(StageError::AlreadyExists)
	));
	let directory = fixture.path(JOB).join(CHECKPOINTS);
	let directory_metadata = fs::metadata(&directory).expect("checkpoint directory metadata");
	assert_eq!(directory_metadata.mode() & 0o7777, 0o700);
	let page_path = directory.join(FIRST_PAGE);
	let page_metadata = fs::metadata(&page_path).expect("checkpoint page metadata");
	assert_eq!(page_metadata.mode() & 0o7777, 0o600);
	assert_eq!(page_metadata.nlink(), 1);
	fixture.assert_debug_redacts(&checkpoints, &[JOB, CHECKPOINTS]);
	drop(job);

	let recovery = root
		.open_recovery_job(job_name())
		.expect("held recovery job");
	let _lease = recovery.try_read_lease().expect("shared job lease");
	let page = recovery.open_checkpoint_page(1).expect("checked page");
	let mut contents = [0; MAX_LENGTH];
	page.read_exact_at(0, &mut contents)
		.expect("read checkpoint data");
	page.check_logical_eof().expect("no bytes beyond the page");
	page.recheck_observation().expect("page inode observation");
	assert_eq!(contents, DATA);
	assert_eq!(page.identity().inode(), page_metadata.ino());
	let mut last = [0];
	recovery
		.open_checkpoint_page(LAST_ORDINAL)
		.expect("last page")
		.read_exact_at(0, &mut last)
		.expect("read last page contents");
	assert_eq!(last, [0x55]);
}

#[test]
fn invalid_page_bounds_leave_no_new_files_and_block_recovery() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination");
	let job = root.create_job_directory(job_name()).expect("private job");
	let checkpoints = job
		.create_checkpoint_directory()
		.expect("private checkpoints");
	let invalid_ordinals = [0, LAST_ORDINAL + 1, u32::MAX];
	for ordinal in invalid_ordinals {
		assert!(matches!(
			checkpoints.write_page(ordinal, &DATA),
			Err(StageError::InvalidCheckpointOrdinal)
		));
	}
	let oversized = [0; MAX_LENGTH + 1];
	let invalid_lengths = [&[][..], &oversized];
	for bytes in invalid_lengths {
		assert!(matches!(
			checkpoints.write_page(1, bytes),
			Err(StageError::InvalidCheckpointPageLength)
		));
	}
	let directory = fixture.path(JOB).join(CHECKPOINTS);
	assert_eq!(
		fs::read_dir(&directory)
			.expect("checkpoint entries")
			.count(),
		0
	);
	drop(job);

	let recovery = root
		.open_recovery_job(job_name())
		.expect("held recovery job");
	let _lease = recovery.try_read_lease().expect("shared job lease");
	for ordinal in invalid_ordinals {
		assert!(matches!(
			recovery.open_checkpoint_page(ordinal),
			Err(StageError::InvalidCheckpointOrdinal)
		));
	}
	let path = directory.join(FIRST_PAGE);
	for bytes in invalid_lengths {
		write_private_fixture(&path, bytes);
		assert!(matches!(
			recovery.open_checkpoint_page(1),
			Err(StageError::InvalidCheckpointPageLength)
		));
		fs::remove_file(&path).expect("reset fixture");
	}
}

#[test]
fn checkpoint_pages_reject_symbolic_and_hard_links() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination");
	let job = root.create_job_directory(job_name()).expect("private job");
	let checkpoints = job
		.create_checkpoint_directory()
		.expect("private checkpoints");
	let page = fixture.path(JOB).join(CHECKPOINTS).join(FIRST_PAGE);
	let incumbent = fixture.path("incumbent");
	write_private_fixture(&incumbent, &DATA);
	symlink(&incumbent, &page).expect("symlink fixture");
	assert!(matches!(
		checkpoints.write_page(1, &[0]),
		Err(StageError::AlreadyExists)
	));
	assert!(page.is_symlink());
	drop(job);

	let recovery = root
		.open_recovery_job(job_name())
		.expect("held recovery job");
	let _lease = recovery.try_read_lease().expect("shared job lease");
	assert!(recovery.open_checkpoint_page(1).is_err());
	fs::remove_file(&page).expect("reset symlink fixture");
	fs::hard_link(&incumbent, &page).expect("hard-link fixture");
	assert!(matches!(
		recovery.open_checkpoint_page(1),
		Err(StageError::UnsafeFile)
	));
	assert_eq!(fs::read(incumbent).expect("incumbent contents"), DATA);
}

#[test]
fn displaced_checkpoint_directory_cannot_write_and_recovery_refuses_symlinks() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination");
	let job = root.create_job_directory(job_name()).expect("private job");
	let checkpoints = job
		.create_checkpoint_directory()
		.expect("private checkpoints");
	let directory = fixture.path(JOB).join(CHECKPOINTS);
	let displaced = fixture.path("displaced-checkpoints");
	fs::rename(&directory, &displaced).expect("move original directory");
	let _replacement = job
		.create_checkpoint_directory()
		.expect("replacement checkpoints");
	assert!(matches!(
		checkpoints.write_page(1, &DATA),
		Err(StageError::IdentityChanged)
	));
	assert!(!directory.join(FIRST_PAGE).exists());
	assert!(!displaced.join(FIRST_PAGE).exists());
	fs::remove_dir(&directory).expect("remove empty replacement");
	symlink(&displaced, &directory).expect("symlink fixture");
	write_private_fixture(&displaced.join(FIRST_PAGE), &DATA);
	assert!(checkpoints.write_page(1, &[0]).is_err());
	drop(job);

	let recovery = root
		.open_recovery_job(job_name())
		.expect("held recovery job");
	let _lease = recovery.try_read_lease().expect("shared job lease");
	assert!(recovery.open_checkpoint_page(1).is_err());
	assert_eq!(
		fs::read(displaced.join(FIRST_PAGE)).expect("displaced page"),
		DATA
	);
}

#[test]
fn held_writer_and_recovery_refuse_a_rebound_job() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination");
	let job = root.create_job_directory(job_name()).expect("private job");
	let checkpoints = job
		.create_checkpoint_directory()
		.expect("private checkpoints");
	let recovery = root
		.open_recovery_job(job_name())
		.expect("held recovery job");
	let displaced = fixture.path("displaced-job");
	fs::rename(fixture.path(JOB), &displaced).expect("rebind private job");
	let replacement = root
		.create_job_directory(job_name())
		.expect("replacement job");
	let new_checkpoints = replacement
		.create_checkpoint_directory()
		.expect("replacement checkpoints");
	new_checkpoints.write_page(1, &[0]).expect("new job page");
	assert!(matches!(
		checkpoints.write_page(1, &DATA),
		Err(StageError::IdentityChanged)
	));
	assert!(matches!(
		recovery.open_checkpoint_page(1),
		Err(StageError::IdentityChanged)
	));
	assert!(!displaced.join(CHECKPOINTS).join(FIRST_PAGE).exists());
}

#[test]
fn guarded_checkpoint_uses_each_effect_and_preserves_the_original_page() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let job = root.create_job_directory(job_name()).unwrap();
	let checkpoints = job.create_checkpoint_directory().unwrap();
	job.sync_directory().unwrap();
	let directory = fixture.path(JOB).join(CHECKPOINTS);
	let selected = directory.join("range-0000004096.cbor");
	let role = ApplyRole::CheckpointPage(LAST_ORDINAL);
	let gate = PageAdmission::new(None);

	checkpoints
		.persist_page_admitted(LAST_ORDINAL, &DATA, &gate)
		.unwrap();
	let original = selected.symlink_metadata().unwrap();
	assert!(original.is_file());
	assert_eq!(original.len(), MAX_LENGTH as u64);
	assert_eq!(original.mode() & 0o7777, 0o600);
	assert_eq!(original.nlink(), 1);
	gate.assert_effects(role, true);

	let conflict = PageAdmission::new(None);
	assert!(matches!(
		checkpoints.persist_page_admitted(LAST_ORDINAL, b"replacement", &conflict),
		Err(StageError::AlreadyExists)
	));
	assert_eq!(&*conflict.steps.borrow(), &[ApplyStep::Create(role)]);
	assert!(!conflict.in_effect.get());
	let incumbent = selected.symlink_metadata().unwrap();
	assert_eq!(
		(incumbent.dev(), incumbent.ino()),
		(original.dev(), original.ino())
	);
	assert_eq!(fs::read_dir(directory).unwrap().count(), 1);
	drop(job);

	let recovery = root.open_recovery_job(job_name()).unwrap();
	let _lease = recovery.try_read_lease().unwrap();
	let page = recovery.open_checkpoint_page(LAST_ORDINAL).unwrap();
	assert_eq!(
		(page.identity().device(), page.identity().inode()),
		(original.dev(), original.ino())
	);
	let mut output = [0; MAX_LENGTH];
	page.read_exact_at(0, &mut output).unwrap();
	page.check_logical_eof().unwrap();
	page.recheck_observation().unwrap();
	assert_eq!(output, DATA);
}

#[test]
fn guarded_checkpoint_refuses_invalid_bounds_before_the_first_effect() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let job = root.create_job_directory(job_name()).unwrap();
	let checkpoints = job.create_checkpoint_directory().unwrap();
	let gate = PageAdmission::new(None);
	for ordinal in [0, LAST_ORDINAL + 1] {
		assert!(matches!(
			checkpoints.persist_page_admitted(ordinal, &[], &gate),
			Err(StageError::InvalidCheckpointOrdinal)
		));
	}
	for bytes in [&[][..], &[0; MAX_LENGTH + 1][..]] {
		assert!(matches!(
			checkpoints.persist_page_admitted(1, bytes, &gate),
			Err(StageError::InvalidCheckpointPageLength)
		));
	}
	assert!(gate.steps.borrow().is_empty());
	assert!(!gate.in_effect.get());
	assert_eq!(
		fs::read_dir(fixture.path(JOB).join(CHECKPOINTS))
			.unwrap()
			.count(),
		0
	);
}

#[test]
fn guarded_checkpoint_refusals_preserve_only_effects_already_submitted() {
	use ApplyStep::{Create, Sync, Write};

	let role = ApplyRole::CheckpointPage(1);
	for (refused, retained) in [
		(Create(role), None),
		(Write(role, 0, MAX_LENGTH), Some(&[][..])),
		(Sync(role), Some(&DATA[..])),
		(Sync(ApplyRole::CheckpointDirectory), Some(&DATA[..])),
	] {
		let fixture = Scratch::new();
		let root = DestinationRoot::from_directory(fixture.open()).unwrap();
		let job = root.create_job_directory(job_name()).unwrap();
		let checkpoints = job.create_checkpoint_directory().unwrap();
		let pages = fixture.path(JOB).join(CHECKPOINTS);
		let original = pages.symlink_metadata().unwrap();
		let path = pages.join(FIRST_PAGE);
		let gate = PageAdmission::new(Some(refused));
		assert!(matches!(
			checkpoints.persist_page_admitted(1, &DATA, &gate),
			Err(StageError::Admission(cause)) if cause.kind() == io::ErrorKind::PermissionDenied
				&& cause.to_string() == "fixture checkpoint refusal"
		));
		gate.assert_effects(role, false);
		assert_eq!(gate.steps.borrow().last(), Some(&refused));
		let current = pages.symlink_metadata().unwrap();
		assert_eq!(
			(current.dev(), current.ino()),
			(original.dev(), original.ino())
		);
		assert_eq!(
			fs::read_dir(&pages).unwrap().count(),
			if retained.is_some() { 1 } else { 0 }
		);
		if let Some(bytes) = retained {
			let record = path.symlink_metadata().unwrap();
			assert!(record.is_file());
			assert_eq!(record.nlink(), 1);
			assert_eq!(fs::read(path).unwrap(), bytes);
		} else {
			assert_eq!(
				path.symlink_metadata().unwrap_err().kind(),
				io::ErrorKind::NotFound
			);
		}
	}
}

struct PageAdmission {
	refuse: Option<ApplyStep>,
	steps: RefCell<Vec<ApplyStep>>,
	in_effect: Cell<bool>,
}

impl PageAdmission {
	fn new(refuse: Option<ApplyStep>) -> Self {
		Self {
			refuse,
			steps: RefCell::default(),
			in_effect: Cell::new(false),
		}
	}

	fn assert_effects(&self, role: ApplyRole, complete: bool) {
		use ApplyStep::{Create, Sync, Write};

		assert!(!self.in_effect.get());
		let steps = self.steps.borrow();
		let [first, tail @ ..] = steps.as_slice() else {
			panic!("expected a guarded exclusive create");
		};
		assert_eq!(*first, Create(role));
		let write_count = tail
			.iter()
			.take_while(|step| **step == Write(role, 0, MAX_LENGTH))
			.count();
		let barriers = &tail[write_count..];
		let full_barriers = [Sync(role), Sync(ApplyRole::CheckpointDirectory)];
		assert!(full_barriers.starts_with(barriers));
		if !barriers.is_empty() {
			assert!(write_count > 0);
		}
		if complete {
			assert_eq!(barriers, &full_barriers);
		}
	}
}

struct PageEffect<'gate>(&'gate Cell<bool>);

impl Drop for PageEffect<'_> {
	fn drop(&mut self) {
		assert!(self.0.replace(false));
	}
}

impl LocalApplyAdmission for PageAdmission {
	type Guard<'gate>
		= PageEffect<'gate>
	where
		Self: 'gate;

	fn enter(&self, step: ApplyStep) -> io::Result<Self::Guard<'_>> {
		assert!(!self.in_effect.get());
		self.steps.borrow_mut().push(step);
		if self.refuse == Some(step) {
			return Err(io::Error::new(
				io::ErrorKind::PermissionDenied,
				"fixture checkpoint refusal",
			));
		}
		self.in_effect.set(true);
		Ok(PageEffect(&self.in_effect))
	}
}

fn job_name() -> UnixComponent<'static> {
	UnixComponent::new(JOB.as_bytes()).expect("fixture job component")
}

fn write_private_fixture(path: &Path, bytes: &[u8]) {
	OpenOptions::new()
		.create_new(true)
		.write(true)
		.mode(0o600)
		.open(path)
		.expect("private fixture record")
		.write_all(bytes)
		.expect("write fixture record");
}

#[path = "../../../../tests/unit/job_checkpoint_scope.rs"]
mod coverage;
