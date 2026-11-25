//! Native Linux checks for destination grant admission and closed-stage integrity.

#![cfg(target_os = "linux")]

mod common;

use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::{FileExt as _, MetadataExt as _, PermissionsExt as _};
use std::time::UNIX_EPOCH;

use exacopy_endpoint::UnixComponent;
use exacopy_model::{
	CopyBinding, CopyEffect, CopyEvent, CopySession, EntryId, JobId, RunEpoch, StageId,
};
use exacopy_platform::linux::{DestinationRoot, PublishError, StageError};
use rustix::process::geteuid;

use common::Scratch;

const INCUMBENT: &[u8] = b"unrelated fixture data";
const PERMISSION_BITS: u32 = 0o7777;
const GROUP_WRITABLE: u32 = 0o770;
const WORLD_WRITABLE: u32 = 0o707;
const STICKY: u32 = 0o1000;
const PRIVATE_DIRECTORY: u32 = 0o700;
const PRIVATE_FILE: u32 = 0o600;

fn name(bytes: &[u8]) -> UnixComponent<'_> {
	UnixComponent::new(bytes).expect("valid fixture component")
}

#[test]
fn destination_intake_rejects_regular_files_and_other_writable_nonsticky_directories() {
	let scratch = Scratch::new();
	let regular = scratch.path("regular-input");
	fs::write(&regular, INCUMBENT).expect("create an unrelated regular file");
	let before = fs::metadata(&regular).expect("inspect the regular file before admission");

	let result = DestinationRoot::from_directory(File::open(&regular).expect("open regular file"));
	assert!(
		matches!(result, Err(StageError::UnsafeDirectory)),
		"regular-file grant: {result:?}"
	);
	let after = fs::metadata(&regular).expect("inspect the regular file after refusal");
	assert_eq!(
		(after.dev(), after.ino(), after.mode()),
		(before.dev(), before.ino(), before.mode())
	);
	assert_eq!(
		fs::read(&regular).expect("read the preserved file"),
		INCUMBENT
	);

	for (directory_name, mode) in [
		("group-writable", GROUP_WRITABLE),
		("world-writable", WORLD_WRITABLE),
	] {
		let path = scratch.path(directory_name);
		fs::create_dir(&path).expect("create an unrelated directory");
		fs::set_permissions(&path, Permissions::from_mode(mode))
			.expect("set exact nonsticky permissions");
		let incumbent = path.join("incumbent");
		fs::write(&incumbent, INCUMBENT).expect("populate the unrelated directory");
		let before = fs::metadata(&path).expect("inspect the directory before admission");

		let result =
			DestinationRoot::from_directory(File::open(&path).expect("open candidate directory"));
		assert!(
			matches!(result, Err(StageError::UnsafeDirectory)),
			"grant for mode {mode:o}: {result:?}"
		);
		let after = fs::metadata(&path).expect("inspect the directory after refusal");
		assert_eq!(
			(after.dev(), after.ino(), after.mode()),
			(before.dev(), before.ino(), before.mode())
		);
		assert_eq!(
			fs::read(&incumbent).expect("read untouched incumbent"),
			INCUMBENT
		);
		assert_eq!(
			fs::read_dir(path)
				.expect("read unchanged directory entries")
				.count(),
			1
		);
	}
}

#[test]
fn destination_intake_accepts_owned_sticky_directories_and_creates_an_exclusive_private_stage() {
	let scratch = Scratch::new();
	let path = scratch.path("sticky-destination");
	fs::create_dir(&path).expect("create a candidate destination");
	let mode = GROUP_WRITABLE | WORLD_WRITABLE | STICKY;
	fs::set_permissions(&path, Permissions::from_mode(mode)).expect("set exact sticky permissions");
	let incumbent = path.join("incumbent");
	fs::write(&incumbent, INCUMBENT).expect("create an unrelated incumbent");
	let before = fs::metadata(&path).expect("inspect the destination before admission");
	assert_eq!(before.uid(), geteuid().as_raw());

	let descriptor = File::open(&path).expect("open the owned sticky directory");
	let destination =
		DestinationRoot::from_directory(descriptor).expect("admit the owned sticky parent");
	scratch.assert_debug_redacts(&destination, &["sticky-destination"]);
	let _stage = destination
		.create_stage_directory(name(b"stage"))
		.expect("create a private stage");
	let stage_path = path.join("stage");
	let stage = fs::metadata(&stage_path).expect("inspect the newly created stage");
	assert_eq!(
		stage.uid(),
		before.uid(),
		"the private stage is owned by the effective user"
	);
	assert_eq!(stage.mode() & PERMISSION_BITS, PRIVATE_DIRECTORY);

	let duplicate = destination.create_stage_directory(name(b"stage"));
	assert!(
		matches!(duplicate, Err(StageError::AlreadyExists)),
		"duplicate stage result: {duplicate:?}"
	);
	assert_eq!(
		fs::metadata(&stage_path)
			.expect("inspect retained stage directory")
			.ino(),
		stage.ino()
	);
	let after = fs::metadata(&path).expect("inspect the destination after staging");
	assert_eq!(
		(after.dev(), after.ino(), after.mode()),
		(before.dev(), before.ino(), before.mode())
	);
	assert_eq!(
		fs::read(&incumbent).expect("read untouched incumbent"),
		INCUMBENT
	);
	assert_eq!(
		fs::read_dir(path)
			.expect("read stage and incumbent")
			.count(),
		2
	);
}

#[test]
fn changing_a_closed_stage_in_place_at_the_same_length_blocks_publication() {
	const VERIFIED: &[u8; 8] = b"verified";
	const REPLACEMENT: &[u8; 8] = b"modified";
	const TARGET: &[u8] = b"target";

	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).expect("admit fixture destination");
	let directory = root
		.create_stage_directory(name(b"stage"))
		.expect("create private stage");
	let binding = CopyBinding::new(
		JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
			.expect("fixture job is UUIDv7"),
		EntryId::new(1),
		RunEpoch::new(1),
		StageId::from_bytes([0x51; 16]),
	);
	let mut session = CopySession::new(binding);
	let mut stage = directory
		.create_file(name(b"part"), name(TARGET), binding)
		.expect("create private file");
	assert!(matches!(
		session.apply(binding, CopyEvent::StagePrepared),
		Ok(Some(CopyEffect::ReadSource(_)))
	));
	stage
		.write_all_at(0, VERIFIED)
		.expect("write original bytes");
	let stage_path = scratch.path("stage").join("part");
	// Use a past modification time so the later write changes the stamp even at coarse precision.
	File::open(&stage_path)
		.expect("open the stage fixture")
		.set_modified(UNIX_EPOCH)
		.expect("set known modification time before the stage is flushed");
	assert_eq!(session.apply(binding, CopyEvent::WritersJoined), Ok(None));
	stage.flush().expect("flush stage bytes");
	assert_eq!(session.apply(binding, CopyEvent::DataFlushed), Ok(None));
	let stage = stage.close_writes().expect("close stage writes");
	let mut readback = [0; VERIFIED.len()];
	stage
		.read_exact_at(0, &mut readback)
		.expect("verify closed stage data");
	assert_eq!(&readback, VERIFIED);
	assert_eq!(
		session.apply(binding, CopyEvent::ReadbackVerified),
		Ok(None)
	);
	let before = fs::metadata(&stage_path).expect("inspect verified private stage");
	assert_eq!(before.mode() & PERMISSION_BITS, PRIVATE_FILE);
	assert_eq!(session.apply(binding, CopyEvent::MetadataReady), Ok(None));
	assert_eq!(session.apply(binding, CopyEvent::StageSealed), Ok(None));

	let mut intent = File::create_new(scratch.path("intent")).expect("create fixture intent");
	intent.write_all(TARGET).expect("record fixture target");
	intent.sync_all().expect("flush fixture intent");
	scratch
		.open()
		.sync_all()
		.expect("flush fixture intent directory");
	let Ok(Some(CopyEffect::PublishNoClobber(authorization))) =
		session.apply(binding, CopyEvent::PublishIntentRecorded)
	else {
		panic!("missing publication authorization for the original stage");
	};

	let outside_writer = OpenOptions::new()
		.write(true)
		.open(&stage_path)
		.expect("open stage as external writer");
	outside_writer
		.write_all_at(REPLACEMENT, 0)
		.expect("replace fixture bytes in place");
	drop(outside_writer);
	let after = fs::metadata(&stage_path).expect("inspect mutated stage");
	assert_eq!(
		(after.dev(), after.ino(), after.len()),
		(before.dev(), before.ino(), before.len())
	);
	assert_ne!(
		after.modified().expect("inspect updated stamp"),
		before.modified().expect("inspect verified stamp")
	);

	let result = stage.publish_no_clobber(authorization);
	assert!(
		matches!(
			result,
			Err(PublishError::StageChanged(StageError::IdentityChanged))
		),
		"changed stage returned {result:?}"
	);
	assert_eq!(
		fs::symlink_metadata(scratch.path("target"))
			.expect_err("modified bytes were published")
			.kind(),
		ErrorKind::NotFound
	);
	assert_eq!(
		fs::read(stage_path).expect("read retained stage evidence"),
		REPLACEMENT
	);
}
