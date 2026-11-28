use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};

use exacopy_endpoint::UnixComponent;

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
