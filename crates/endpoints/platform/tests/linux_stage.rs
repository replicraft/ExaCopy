//! Native Linux stage ownership, read-back, and exclusive publication.

#![cfg(target_os = "linux")]

mod common;

use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, symlink};
use std::path::Path;

use exacopy_endpoint::{IoError, UnixComponent};
use exacopy_model::{
	CopyBinding, CopyEffect, CopyEvent, CopySession, EntryId, JobId, PublishNoClobber, RunEpoch,
	StageId,
};
use exacopy_platform::linux::{
	ClosedStage, DestinationRoot, PublishError, StageDirectory, StageError, WriteStage,
};

use common::Scratch;

const STAGE_DIRECTORY: &str = "private-stage";
const STAGE_FILE: &str = "private-part";
const TARGET: &str = "target";
const DATA: &[u8; 8] = b"verified";
const EXISTING: &[u8] = b"incumbent";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const PERMISSION_BITS: u32 = 0o7777;

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).expect("valid fixture component")
}

fn stage_directory(destination: &DestinationRoot) -> StageDirectory<'_> {
	destination
		.create_stage_directory(component(STAGE_DIRECTORY))
		.expect("create stage directory")
}

fn binding(entry: u64) -> CopyBinding {
	let job = JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
		.expect("fixture job is UUIDv7");
	CopyBinding::new(
		job,
		EntryId::new(entry),
		RunEpoch::new(1),
		StageId::from_bytes([0x51; 16]),
	)
}

fn observe(session: &mut CopySession, binding: CopyBinding, event: CopyEvent) {
	assert_eq!(
		session.apply(binding, event),
		Ok(None),
		"observation {event:?}"
	);
}

fn prepare_for_publication<'stage>(
	mut writable: WriteStage<'stage>,
	binding: CopyBinding,
	target: UnixComponent<'_>,
	scratch: &Scratch,
) -> (ClosedStage<'stage>, PublishNoClobber) {
	let mut session = CopySession::new(binding);
	assert!(matches!(
		session.apply(binding, CopyEvent::StagePrepared),
		Ok(Some(CopyEffect::ReadSource(request))) if request.binding() == binding
	));
	writable.write_all_at(0, DATA).expect("write stage payload");
	observe(&mut session, binding, CopyEvent::WritersJoined);
	writable.flush().expect("flush stage payload");
	observe(&mut session, binding, CopyEvent::DataFlushed);
	let stage = writable.close_writes().expect("close stage writes");
	let mut readback = [0; DATA.len()];
	stage
		.read_exact_at(0, &mut readback)
		.expect("read closed stage");
	assert_eq!(&readback, DATA);
	observe(&mut session, binding, CopyEvent::ReadbackVerified);
	let stage_path = scratch.path(STAGE_DIRECTORY).join(STAGE_FILE);
	let metadata = fs::metadata(stage_path).expect("verify fixture stage mode");
	assert_eq!(metadata.mode() & PERMISSION_BITS, PRIVATE_FILE_MODE);
	observe(&mut session, binding, CopyEvent::MetadataReady);
	observe(&mut session, binding, CopyEvent::StageSealed);

	// A test marker backs this fixture observation. The adapter has no journal protocol.
	let mut intent = File::create_new(scratch.path("test-publication-intent"))
		.expect("create the fixture intent marker");
	intent
		.write_all(target.as_bytes())
		.expect("record fixture target");
	intent.sync_all().expect("flush intent marker");
	scratch
		.open()
		.sync_all()
		.expect("flush intent marker directory");
	let Ok(Some(CopyEffect::PublishNoClobber(authorization))) =
		session.apply(binding, CopyEvent::PublishIntentRecorded)
	else {
		panic!("the model did not authorize the prepared fixture");
	};
	(stage, authorization)
}

fn create_private_file(path: &Path, data: &[u8]) {
	let mut file = OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(PRIVATE_FILE_MODE)
		.open(path)
		.expect("create independent private fixture");
	file.write_all(data)
		.expect("populate independent private fixture");
}

#[test]
fn stages_use_private_modes_and_support_out_of_order_positioned_write_and_read_back() {
	let scratch = Scratch::new();
	let destination =
		DestinationRoot::from_directory(scratch.open()).expect("open destination root");
	let directory = stage_directory(&destination);
	let mut stage = directory
		.create_file(component(STAGE_FILE), component(TARGET), binding(1))
		.expect("create stage");
	let stage_directory = scratch.path(STAGE_DIRECTORY);
	let stage_path = stage_directory.join(STAGE_FILE);
	let directory_mode = fs::metadata(stage_directory)
		.expect("inspect stage directory")
		.mode();
	let stage_mode = fs::metadata(&stage_path)
		.expect("inspect stage file")
		.mode();
	assert_eq!(directory_mode & PERMISSION_BITS, PRIVATE_DIRECTORY_MODE);
	assert_eq!(stage_mode & PERMISSION_BITS, PRIVATE_FILE_MODE);

	stage.set_len(10).expect("size stage");
	stage
		.write_all_at(6, b"last")
		.expect("write trailing range first");
	stage
		.write_all_at(0, b"head")
		.expect("write leading range second");
	assert!(matches!(
		stage.write_all_at(u64::MAX, b"!"),
		Err(IoError::InvalidRange {
			offset: u64::MAX,
			length: 1
		})
	));
	stage.flush().expect("flush stage");
	let stage = stage.close_writes().expect("close write access");

	let mut range = [0; 4];
	stage
		.read_exact_at(6, &mut range)
		.expect("read trailing range");
	assert_eq!(&range, b"last");
	stage
		.read_exact_at(0, &mut range)
		.expect("read leading range");
	assert_eq!(&range, b"head");
	assert_eq!(
		fs::read(&stage_path).expect("read independent stage view"),
		b"head\0\0last"
	);
}

#[test]
fn existing_stage_directory_and_its_contents_are_preserved_without_adoption() {
	let scratch = Scratch::new();
	let existing = scratch.path(STAGE_DIRECTORY);
	DirBuilder::new()
		.mode(PRIVATE_DIRECTORY_MODE)
		.create(&existing)
		.expect("create private-looking incumbent directory");
	let incumbent = existing.join(STAGE_FILE);
	create_private_file(&incumbent, EXISTING);
	let before = fs::metadata(&incumbent).expect("inspect incumbent before staging");
	let destination =
		DestinationRoot::from_directory(scratch.open()).expect("open destination root");
	let result = destination.create_stage_directory(component(STAGE_DIRECTORY));

	assert!(
		matches!(result, Err(StageError::AlreadyExists)),
		"unexpected stage result: {result:?}"
	);
	assert_eq!(
		fs::metadata(&incumbent)
			.expect("inspect incumbent after staging")
			.ino(),
		before.ino()
	);
	assert_eq!(
		fs::read(incumbent).expect("read retained incumbent"),
		EXISTING
	);
}

#[test]
fn creating_a_stage_file_never_adopts_an_incumbent_in_the_private_directory() {
	let scratch = Scratch::new();
	let destination =
		DestinationRoot::from_directory(scratch.open()).expect("open destination root");
	let directory = stage_directory(&destination);
	let incumbent = scratch.path(STAGE_DIRECTORY).join(STAGE_FILE);
	create_private_file(&incumbent, EXISTING);
	let before = fs::metadata(&incumbent).expect("inspect incumbent before creation");

	let result = directory.create_file(component(STAGE_FILE), component(TARGET), binding(1));
	assert!(
		matches!(result, Err(StageError::AlreadyExists)),
		"unexpected stage result: {result:?}"
	);
	assert_eq!(
		fs::metadata(&incumbent)
			.expect("inspect incumbent after creation")
			.ino(),
		before.ino()
	);
	assert_eq!(
		fs::read(incumbent).expect("read retained incumbent"),
		EXISTING
	);
}

#[test]
fn stage_close_requires_a_full_flush_after_the_last_write_or_resize() {
	let scratch = Scratch::new();
	let destination =
		DestinationRoot::from_directory(scratch.open()).expect("open destination root");
	let directory = stage_directory(&destination);
	let pending = directory
		.create_file(component("pending"), component(TARGET), binding(1))
		.expect("create unflushed stage");
	assert!(matches!(pending.close_writes(), Err(StageError::Unflushed)));

	let mut rewritten = directory
		.create_file(component("rewritten"), component(TARGET), binding(2))
		.expect("create stage for write");
	rewritten.flush().expect("flush stage before write");
	rewritten.write_all_at(0, DATA).expect("write after flush");
	assert!(matches!(
		rewritten.close_writes(),
		Err(StageError::Unflushed)
	));

	let mut resized = directory
		.create_file(component("resized"), component(TARGET), binding(3))
		.expect("create stage for resize");
	resized.flush().expect("flush stage before resize");
	resized.set_len(20).expect("resize after flush");
	assert!(matches!(resized.close_writes(), Err(StageError::Unflushed)));
}

#[test]
fn renames_the_authorized_stage_to_an_absent_target_preserving_exact_identity() {
	let scratch = Scratch::new();
	let raw_target = b"raw-target-\xff";
	let mut selected_target = *raw_target;
	let target = UnixComponent::new(&selected_target).expect("valid raw target component");
	let names = [STAGE_DIRECTORY, STAGE_FILE, "raw-target-"];
	let destination =
		DestinationRoot::from_directory(scratch.open()).expect("open destination root");
	let directory = stage_directory(&destination);
	scratch.assert_debug_redacts(&destination, &names);
	scratch.assert_debug_redacts(&directory, &names);
	let binding = binding(1);
	let stage = directory
		.create_file(component(STAGE_FILE), target, binding)
		.expect("create stage");
	selected_target.fill(b'x');
	scratch.assert_debug_redacts(&stage, &names);
	let target = UnixComponent::new(raw_target).expect("valid target recorded in intent");
	let (stage, authorization) = prepare_for_publication(stage, binding, target, &scratch);
	scratch.assert_debug_redacts(&stage, &names);
	let stage_path = scratch.path(STAGE_DIRECTORY).join(STAGE_FILE);
	let original = fs::metadata(&stage_path).expect("inspect stage identity before publication");
	let target_path = scratch.path(OsStr::from_bytes(raw_target));

	stage
		.publish_no_clobber(authorization)
		.expect("publish with the bound authorization");

	let published = fs::metadata(&target_path).expect("inspect published object");
	assert_eq!(
		(published.dev(), published.ino()),
		(original.dev(), original.ino())
	);
	assert_eq!(published.nlink(), 1, "only the final link should remain");
	assert_eq!(fs::read(&target_path).expect("read publication"), DATA);
	assert!(!scratch.path(OsStr::from_bytes(&selected_target)).exists());
	assert_eq!(
		fs::symlink_metadata(stage_path)
			.expect_err("stage name was not retired")
			.kind(),
		ErrorKind::NotFound
	);
}

#[test]
fn a_late_incumbent_file_link_or_directory_keeps_its_identity_and_the_stage_survives() {
	enum Incumbent {
		File,
		HardLink,
		Symlink,
		Directory,
	}

	for incumbent in [
		Incumbent::File,
		Incumbent::HardLink,
		Incumbent::Symlink,
		Incumbent::Directory,
	] {
		let scratch = Scratch::new();
		let destination =
			DestinationRoot::from_directory(scratch.open()).expect("open destination root");
		let directory = stage_directory(&destination);
		let binding = binding(1);
		let stage = directory
			.create_file(component(STAGE_FILE), component(TARGET), binding)
			.expect("create stage");
		let (stage, authorization) =
			prepare_for_publication(stage, binding, component(TARGET), &scratch);
		let stage_path = scratch.path(STAGE_DIRECTORY).join(STAGE_FILE);
		let stage_identity = fs::metadata(&stage_path).expect("inspect stage prior to conflict");
		let target = scratch.path(TARGET);
		let original_source = scratch.path("original-source");
		create_private_file(&original_source, EXISTING);

		// The namespace changes after authorization but before the exclusive syscall.
		let payload = match incumbent {
			Incumbent::File => {
				create_private_file(&target, EXISTING);
				target.clone()
			}
			Incumbent::HardLink => {
				fs::hard_link(&original_source, &target).expect("create a hard-link incumbent");
				target.clone()
			}
			Incumbent::Symlink => {
				symlink("original-source", &target).expect("create a symlink incumbent");
				target.clone()
			}
			Incumbent::Directory => {
				fs::create_dir(&target).expect("create a directory incumbent");
				create_private_file(&target.join("child"), EXISTING);
				target.join("child")
			}
		};
		let before = fs::symlink_metadata(&target).expect("inspect incumbent without following");
		let result = stage.publish_no_clobber(authorization);

		assert!(
			matches!(result, Err(PublishError::Conflict)),
			"unexpected publication outcome: {result:?}"
		);
		let after = fs::symlink_metadata(&target).expect("inspect retained incumbent");
		assert_eq!(
			(after.dev(), after.ino(), after.mode()),
			(before.dev(), before.ino(), before.mode())
		);
		assert_eq!(fs::read(payload).expect("read incumbent payload"), EXISTING);
		assert_eq!(
			fs::read(original_source).expect("read preserved source bytes"),
			EXISTING
		);
		assert_eq!(
			fs::metadata(&stage_path)
				.expect("inspect retained stage")
				.ino(),
			stage_identity.ino()
		);
		assert_eq!(
			fs::read(stage_path).expect("read retained stage bytes"),
			DATA
		);
	}
}

#[test]
fn rebinding_the_private_file_or_directory_prevents_publication_and_preserves_both_objects() {
	enum Rebind {
		File,
		Directory,
	}

	for rebind in [Rebind::File, Rebind::Directory] {
		let scratch = Scratch::new();
		let destination =
			DestinationRoot::from_directory(scratch.open()).expect("open destination root");
		let directory = stage_directory(&destination);
		let binding = binding(1);
		let stage = directory
			.create_file(component(STAGE_FILE), component(TARGET), binding)
			.expect("create stage");
		let (stage, authorization) =
			prepare_for_publication(stage, binding, component(TARGET), &scratch);
		let directory_path = scratch.path(STAGE_DIRECTORY);
		let stage_path = directory_path.join(STAGE_FILE);
		let moved_path = match rebind {
			Rebind::File => {
				let moved = directory_path.join("moved");
				fs::rename(&stage_path, &moved).expect("move stage out of its original name");
				moved
			}
			Rebind::Directory => {
				let moved = scratch.path("moved");
				fs::rename(&directory_path, &moved).expect("move stage directory");
				DirBuilder::new()
					.mode(PRIVATE_DIRECTORY_MODE)
					.create(directory_path)
					.expect("create replacement directory");
				moved.join(STAGE_FILE)
			}
		};
		create_private_file(&stage_path, EXISTING);
		let result = stage.publish_no_clobber(authorization);

		assert!(
			matches!(
				result,
				Err(PublishError::StageChanged(StageError::IdentityChanged))
			),
			"unexpected result for rebound stage: {result:?}"
		);
		assert_eq!(
			fs::symlink_metadata(scratch.path(TARGET))
				.expect_err("rebound stage published")
				.kind(),
			ErrorKind::NotFound
		);
		assert_eq!(
			fs::read(stage_path).expect("read replacement stage name"),
			EXISTING
		);
		assert_eq!(
			fs::read(moved_path).expect("read retained original stage"),
			DATA
		);
	}
}

#[test]
fn a_genuine_authorization_for_another_binding_cannot_publish_this_stage() {
	let scratch = Scratch::new();
	let destination =
		DestinationRoot::from_directory(scratch.open()).expect("open destination root");
	let directory = stage_directory(&destination);
	let own_binding = binding(1);
	let stage = directory
		.create_file(component(STAGE_FILE), component(TARGET), own_binding)
		.expect("create stage");
	let (stage, _own_authorization) =
		prepare_for_publication(stage, own_binding, component(TARGET), &scratch);

	let other_scratch = Scratch::new();
	let other_destination =
		DestinationRoot::from_directory(other_scratch.open()).expect("open other destination root");
	let other_directory = stage_directory(&other_destination);
	let other_binding = binding(2);
	let other_stage = other_directory
		.create_file(component(STAGE_FILE), component(TARGET), other_binding)
		.expect("create other stage");
	let (_other_stage, other_authorization) = prepare_for_publication(
		other_stage,
		other_binding,
		component(TARGET),
		&other_scratch,
	);

	let result = stage.publish_no_clobber(other_authorization);

	assert!(
		matches!(result, Err(PublishError::BindingMismatch)),
		"wrong-binding result: {result:?}"
	);
	assert_eq!(
		fs::symlink_metadata(scratch.path(TARGET))
			.expect_err("wrong binding published")
			.kind(),
		ErrorKind::NotFound
	);
	assert_eq!(
		fs::read(scratch.path(STAGE_DIRECTORY).join(STAGE_FILE)).expect("read retained stage"),
		DATA
	);
}
