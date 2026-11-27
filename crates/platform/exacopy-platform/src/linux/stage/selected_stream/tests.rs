use std::fs::{self, File, FileTimes, Permissions};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::time::{Duration, SystemTime};

use exacopy_endpoint::UnixComponent;
use exacopy_model::{CopyBinding, EntryId, JobId, RunEpoch, StageId};
use rustix::fs::{XattrFlags, fsetxattr};
use rustix::io::Errno;

use super::{StageHandle, check_metadata, prepare};
use crate::linux::job::STAGE;
use crate::linux::source::SourceObservation;
use crate::linux::{ClosedStage, DestinationRoot, StageDirectory, StageError};
use crate::scratch::Scratch;

#[path = "../../../../tests/unit/linux_selected_stream_admission.rs"]
mod admission;

const DIRECTORY: &str = "selected-stage";
const PART: &str = "selected-part";
const TARGET: &str = "selected-target";
const JOB: &str = "selected-job";
const PAYLOAD: &[u8] = b"selected stream";

#[test]
fn holds_the_original_stage_and_reports_the_local_profile() {
	for bytes in [&[][..], PAYLOAD] {
		let scratch = Scratch::new();
		let root = DestinationRoot::from_directory(scratch.open()).unwrap();
		let directory = root.create_stage_directory(component(DIRECTORY)).unwrap();
		let stage = stage(&directory, bytes);
		let identity = stage.identity();
		let length = stage.length();
		let location = stage.inspect_selected_stream_location().unwrap();
		assert_eq!(location.binding, binding());
		assert_eq!(location.stage, identity);
		assert_eq!(location.directory, directory.identity());
		assert_eq!(location.destination, root.identity());
		assert_eq!(location.names.stage, component(PART));
		assert_eq!(location.names.target, component(TARGET));

		let ready = stage.prepare_selected_stream_metadata(length).unwrap();
		let names = ready.names().unwrap();
		assert_eq!(names.stage, component(PART));
		assert_eq!(names.target, component(TARGET));
		let seen = ready.observed();
		assert_eq!(seen.binding(), binding());
		assert_eq!(seen.destination(), root.identity());
		assert_eq!(seen.stage_directory(), directory.identity());
		assert_eq!(seen.stage(), identity);
		assert_eq!(seen.length(), length);
		assert_eq!(seen.owner(), rustix::process::geteuid().as_raw());
		assert_eq!(seen.group(), rustix::process::getegid().as_raw());
		assert_eq!(seen.mode(), 0o600);
		ready.recheck().unwrap();
		assert_eq!(fs::read(scratch.path(DIRECTORY).join(PART)).unwrap(), bytes);
		assert!(!scratch.path(TARGET).exists());
	}
}

#[test]
fn refuses_length_mismatch_before_sync_and_retains_both_paths() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let directory = root.create_stage_directory(component(DIRECTORY)).unwrap();
	let stage = stage(&directory, PAYLOAD);
	let count = stage.length();
	fs::write(scratch.path(TARGET), b"incumbent").unwrap();

	let result = prepare(StageHandle::Closed(stage), count + 1, |_| {
		panic!("an invalid extent must fail before fsync")
	});
	assert!(matches!(result, Err(StageError::MetadataMismatch)));
	assert_eq!(
		fs::read(scratch.path(DIRECTORY).join(PART)).unwrap(),
		PAYLOAD
	);
	assert_eq!(fs::read(scratch.path(TARGET)).unwrap(), b"incumbent");
}

#[test]
fn detects_failed_barrier_and_drift_after_a_completed_barrier() {
	for fail_sync in [true, false] {
		let scratch = Scratch::new();
		let root = DestinationRoot::from_directory(scratch.open()).unwrap();
		let directory = root.create_stage_directory(component(DIRECTORY)).unwrap();
		let stage = stage(&directory, PAYLOAD);
		let length = stage.length();
		let path = scratch.path(DIRECTORY).join(PART);
		let result = prepare(StageHandle::Closed(stage), length, |file| {
			if fail_sync {
				return Err(Errno::IO);
			}
			rustix::fs::fsync(file)?;
			fs::write(&path, vec![b'r'; PAYLOAD.len()]).unwrap();
			File::open(&path)
				.unwrap()
				.set_times(
					FileTimes::new().set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
				)
				.unwrap();
			Ok(())
		});
		if fail_sync {
			assert!(matches!(result, Err(StageError::BarrierFailed(_))));
			assert_eq!(fs::read(path).unwrap(), PAYLOAD);
		} else {
			assert!(matches!(result, Err(StageError::IdentityChanged)));
			assert_eq!(fs::read(path).unwrap(), vec![b'r'; PAYLOAD.len()]);
		}
		assert!(!scratch.path(TARGET).exists());
	}
}

#[test]
fn recheck_refuses_changed_name_attributes_and_hard_links() {
	for change in 0..3 {
		let scratch = Scratch::new();
		let root = DestinationRoot::from_directory(scratch.open()).unwrap();
		let directory = root.create_stage_directory(component(DIRECTORY)).unwrap();
		let stage = stage(&directory, PAYLOAD);
		let count = stage.length();
		let ready = stage.prepare_selected_stream_metadata(count).unwrap();
		let part = scratch.path(DIRECTORY).join(PART);
		let second = scratch.path(DIRECTORY).join("preserved-inode");
		match change {
			0 => {
				let original = fs::metadata(&part).unwrap();
				fs::rename(&part, &second).unwrap();
				fs::write(&part, b"new occupant").unwrap();
				let replacement = fs::metadata(&part).unwrap();
				assert!(matches!(ready.recheck(), Err(StageError::IdentityChanged)));
				let preserved = fs::metadata(&second).unwrap();
				assert_eq!(
					(preserved.dev(), preserved.ino()),
					(original.dev(), original.ino())
				);
				let after = fs::metadata(&part).unwrap();
				assert_eq!(
					(after.dev(), after.ino()),
					(replacement.dev(), replacement.ino())
				);
				assert_eq!(fs::read(&part).unwrap(), b"new occupant");
			}
			1 => {
				fsetxattr(
					File::open(&part).unwrap(),
					c"user.exacopy",
					b"visible",
					XattrFlags::CREATE,
				)
				.unwrap();
				assert!(ready.recheck().is_err());
			}
			_ => {
				fs::hard_link(&part, &second).unwrap();
				assert!(matches!(ready.recheck(), Err(StageError::UnsafeFile)));
			}
		}
		if change != 1 {
			assert_eq!(fs::read(second).unwrap(), PAYLOAD);
		}
		assert!(!scratch.path(TARGET).exists());
	}
}

#[test]
fn rejects_a_visible_attribute_in_the_original_closed_observation() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let directory = root.create_stage_directory(component(DIRECTORY)).unwrap();
	let mut writer = directory
		.create_file(component(PART), component(TARGET), binding())
		.unwrap();
	writer.write_all_at(0, PAYLOAD).unwrap();
	let path = scratch.path(DIRECTORY).join(PART);
	fsetxattr(
		File::open(&path).unwrap(),
		c"user.exacopy",
		b"visible",
		XattrFlags::CREATE,
	)
	.unwrap();
	writer.flush().unwrap();
	let closed = writer.close_writes().unwrap();
	let length = closed.length();
	let result = prepare(StageHandle::Closed(closed), length, |_| {
		panic!("visible attributes must fail before fsync")
	});
	assert!(matches!(
		result,
		Err(StageError::UnexpectedExtendedAttributes)
	));
	assert_eq!(fs::read(path).unwrap(), PAYLOAD);
	assert!(!scratch.path(TARGET).exists());
}

#[test]
fn strict_policy_rejects_wrong_uid_gid_and_special_mode_bits() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let directory = root.create_stage_directory(component(DIRECTORY)).unwrap();
	let stage = stage(&directory, PAYLOAD);
	let view = stage.selected_stream_view().unwrap();
	let stat = rustix::fs::fstat(view.file).unwrap();
	let mut wrong_uid = stat;
	wrong_uid.st_uid ^= 1;
	let mut wrong_gid = stat;
	wrong_gid.st_gid ^= 1;
	let mut special_mode = stat;
	special_mode.st_mode |= 0o4000;
	for changed in [wrong_uid, wrong_gid, special_mode] {
		let captured = SourceObservation::capture(&changed).unwrap();
		assert!(matches!(
			check_metadata(&changed, captured),
			Err(StageError::UnsafeFile)
		));
	}
}

#[test]
fn retained_stage_keeps_the_recovery_lease_and_requires_exact_mode() {
	for mode in [0o600, 0o640] {
		let scratch = Scratch::new();
		let root = DestinationRoot::from_directory(scratch.open()).unwrap();
		{
			let job = root.create_job_directory(component(JOB)).unwrap();
			let directory = job.create_stage_directory().unwrap();
			let stage = stage(&directory, PAYLOAD);
			drop(stage);
		}
		let path = scratch.path(JOB).join(STAGE).join(PART);
		fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
		let job = root.open_recovery_job(component(JOB)).unwrap();
		let lease = root
			.try_recovery_write_lease(component(JOB), job.identity())
			.unwrap();
		let inventory = lease
			.job()
			.inventory(component(PART), component(TARGET))
			.unwrap();
		let file = inventory.stage().unwrap();
		let mut bytes = [0; PAYLOAD.len()];
		file.read_exact_at(0, &mut bytes).unwrap();
		file.check_logical_eof().unwrap();
		assert_eq!(bytes, PAYLOAD);
		let retained = lease.prepare_retained_stage(&inventory, binding()).unwrap();
		if mode == 0o600 {
			let location = retained.inspect_selected_stream_location().unwrap();
			assert_eq!(location.binding, binding());
			assert_eq!(location.stage, file.identity());
			assert_eq!(
				location.directory,
				inventory.stage_directory_identity().unwrap()
			);
			assert_eq!(location.destination, root.identity());
			assert_eq!(location.names.stage, component(PART));
			assert_eq!(location.names.target, component(TARGET));
		} else {
			assert!(matches!(
				retained.inspect_selected_stream_location(),
				Err(StageError::UnsafeFile)
			));
		}
		let selected = retained.prepare_selected_stream_metadata(file.len());
		if mode == 0o600 {
			let ready = selected.unwrap();
			assert_eq!(ready.observed().stage(), file.identity());
			assert_eq!(
				ready.observed().stage_directory(),
				inventory.stage_directory_identity().unwrap()
			);
			assert!(matches!(
				lease.prepare_retained_stage(&inventory, binding()),
				Err(StageError::JobBusy)
			));
			ready.recheck().unwrap();
		} else {
			assert!(matches!(selected, Err(StageError::UnsafeFile)));
		}
		assert_eq!(fs::read(path).unwrap(), PAYLOAD);
		assert!(!scratch.path(TARGET).exists());
	}
}

fn stage<'stage>(directory: &'stage StageDirectory<'stage>, bytes: &[u8]) -> ClosedStage<'stage> {
	let mut stage = directory
		.create_file(component(PART), component(TARGET), binding())
		.unwrap();
	if !bytes.is_empty() {
		stage.write_all_at(0, bytes).unwrap();
	}
	stage.flush().unwrap();
	stage.close_writes().unwrap()
}

fn binding() -> CopyBinding {
	CopyBinding::new(
		JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1]).unwrap(),
		EntryId::new(1),
		RunEpoch::new(1),
		StageId::from_bytes([0x73; 16]),
	)
}

fn component(value: &str) -> UnixComponent<'_> {
	UnixComponent::new(value.as_bytes()).unwrap()
}
