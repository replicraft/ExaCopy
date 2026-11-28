use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, symlink};

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_recovery::{
	ApplyContinuity, ApplyNameObservation, HeldPublicApplyNames,
};

use crate::linux::DestinationRoot;
use crate::scratch::Scratch;

use super::*;

#[test]
fn records_refuse_same_byte_rebound_parent_under_original_shared_lease() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let name = UnixComponent::new(b"checked-reconciliation-job").unwrap();
	let job = root.create_job_directory(name).unwrap();
	drop(job);
	let job_path = scratch.path("checked-reconciliation-job");
	let job = root.open_recovery_job(name).unwrap();
	let lease = job.try_read_lease().unwrap();
	let view = lease.public_apply_view(None);
	for (parent, child) in [(JOURNAL, FIRST_SEGMENT), (RECEIPTS, RECEIPT)] {
		let path = job_path.join(parent);
		let moved = job_path.join(format!("{parent}-original"));
		let bytes = b"retained original bytes";
		let write = |parent: &std::path::Path| {
			DirBuilder::new().mode(0o700).create(parent).unwrap();
			let mut file = OpenOptions::new()
				.create_new(true)
				.write(true)
				.mode(0o600)
				.open(parent.join(child))
				.unwrap();
			file.write_all(bytes).unwrap();
		};
		write(&path);
		let records = view.hold_apply_records().unwrap();
		records.recheck_records().unwrap();
		let original = fs::metadata(&path).unwrap().ino();
		fs::rename(&path, &moved).unwrap();
		write(&path);
		assert_ne!(fs::metadata(&path).unwrap().ino(), original);
		assert_eq!(fs::metadata(&moved).unwrap().ino(), original);
		assert!(matches!(
			records.recheck_records(),
			Err(StageError::IdentityChanged)
		));
		assert_eq!(fs::read(moved.join(child)).unwrap(), bytes);
		assert_eq!(fs::read(path.join(child)).unwrap(), bytes);
	}
}

#[test]
fn metadata_target_rebind_to_symlink_of_original_is_refused() {
	let scratch = Scratch::new();
	let root = DestinationRoot::from_directory(scratch.open()).unwrap();
	let job_name = UnixComponent::new(b"checked-reconciliation-target").unwrap();
	drop(root.create_job_directory(job_name).unwrap());
	let job = root.open_recovery_job(job_name).unwrap();
	let lease = job.try_read_lease().unwrap();
	let view = lease.public_apply_view(None);
	let source = scratch.path("source");
	let target = scratch.path("target");
	let retained = scratch.path("retained-target");
	let source_bytes = b"unchanged source";
	let incumbent_bytes = b"unchanged incumbent";
	fs::write(&source, source_bytes).unwrap();
	fs::write(&target, incumbent_bytes).unwrap();
	let original = fs::symlink_metadata(&target).unwrap();
	let source_before = fs::symlink_metadata(&source).unwrap();
	let root_identity = root.identity();
	let target_identity = JobFileIdentity {
		device: original.dev(),
		inode: original.ino(),
	};
	let selection = ApplyNamesSelection {
		stage: UnixComponent::new(b"payload").unwrap(),
		target: UnixComponent::new(b"target").unwrap(),
		candidate: Some(target_identity),
		source_root: root_identity.into(),
		environment: None,
		required: None,
	};
	let names = view.pin_apply_names(selection).unwrap();
	assert_eq!(names.continuity(), ApplyContinuity::Unqualified);
	assert!(matches!(names.stage(), ApplyNameObservation::Absent));
	assert!(matches!(names.target(), ApplyNameObservation::Present(id) if id == target_identity));
	names.recheck_names().unwrap();

	// Following the replacement would still resolve to the original inode.
	fs::rename(&target, &retained).unwrap();
	symlink("retained-target", &target).unwrap();
	let alias = fs::metadata(&target).unwrap();
	assert_eq!((alias.dev(), alias.ino()), (original.dev(), original.ino()));
	assert!(matches!(
		names.recheck_names(),
		Err(StageError::IdentityChanged)
	));

	let rebound = fs::symlink_metadata(&target).unwrap();
	assert!(rebound.is_symlink());
	assert_ne!(
		(rebound.dev(), rebound.ino()),
		(original.dev(), original.ino())
	);
	let current = view.pin_apply_names(selection).unwrap();
	assert!(matches!(
		current.target(),
		ApplyNameObservation::Present(id) if (id.device, id.inode) == (rebound.dev(), rebound.ino())
	));
	current.recheck_names().unwrap();
	assert_eq!(
		fs::read_link(&target).unwrap().as_os_str(),
		retained.file_name().unwrap()
	);

	for (path, before, expected) in [
		(&retained, original, incumbent_bytes.as_slice()),
		(&source, source_before, source_bytes.as_slice()),
	] {
		let after = fs::symlink_metadata(path).unwrap();
		assert!(after.is_file());
		assert_eq!(
			(after.dev(), after.ino(), after.len()),
			(before.dev(), before.ino(), before.len())
		);
		assert_eq!(
			(after.atime(), after.atime_nsec()),
			(before.atime(), before.atime_nsec())
		);
		assert_eq!(fs::read(path).unwrap(), expected);
	}
}
