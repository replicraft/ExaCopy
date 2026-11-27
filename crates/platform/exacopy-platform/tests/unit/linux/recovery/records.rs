use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::symlink;

use exacopy_endpoint::linux_recovery::RecoveryJobView;

use crate::linux::StageError;
use crate::linux::job::{CHECKPOINTS, RECEIPT, RECEIPTS, checkpoint_page_name};

use super::{JOB, assert_read_only, fixture, name, private_directory, private_file};

#[test]
fn optional_receipt_distinguishes_absence_from_an_unsafe_candidate() {
	let (fixture, root) = fixture();
	let job = root
		.open_recovery_job(name(JOB))
		.expect("open recovery job");
	let observe = || RecoveryJobView::open_optional_receipt(&job);
	assert!(
		observe()
			.expect("observe absent receipt directory")
			.is_none()
	);

	let directory = fixture.path(JOB).join(RECEIPTS);
	private_directory(&directory);
	assert!(observe().expect("observe absent receipt file").is_none());

	let incumbent = fixture.path("incumbent");
	let receipt = directory.join(RECEIPT);
	private_file(&incumbent, b"incumbent data");
	symlink(&incumbent, &receipt).expect("install unsafe receipt candidate");
	assert!(matches!(observe(), Err(StageError::UnsafeFile)));
	assert_eq!(
		fs::read(&incumbent).expect("read preserved incumbent"),
		b"incumbent data"
	);

	fs::remove_file(&receipt).expect("remove fixture symlink");
	const BYTES: &[u8] = b"receipt evidence";
	private_file(&receipt, BYTES);
	let file = observe()
		.expect("reopen receipt record")
		.expect("observe new regular receipt");
	assert_read_only(&file);
	let mut observed = [0; BYTES.len()];
	file.read_exact_at(0, &mut observed).expect("read receipt");
	assert_eq!(&observed, BYTES);
}

#[test]
fn checkpoint_reader_distinguishes_invalid_ordinal_absence_and_empty_record() {
	let (fixture, root) = fixture();
	let job = root
		.open_recovery_job(name(JOB))
		.expect("open recovery job");
	assert!(matches!(
		job.open_checkpoint_page(0),
		Err(StageError::InvalidCheckpointOrdinal)
	));

	let checkpoints = fixture.path(JOB).join(CHECKPOINTS);
	private_directory(&checkpoints);
	let ordinal = 1;
	let path = checkpoints.join(checkpoint_page_name(ordinal).expect("valid fixture ordinal"));
	assert!(matches!(
		job.open_checkpoint_page(ordinal),
		Err(StageError::System(error)) if error.kind() == ErrorKind::NotFound
	));

	private_file(&path, b"");
	assert!(matches!(
		job.open_checkpoint_page(ordinal),
		Err(StageError::InvalidCheckpointPageLength)
	));
	assert_eq!(fs::read(&path).expect("read retained empty record"), b"");

	const BYTES: &[u8] = b"checkpoint evidence";
	fs::write(&path, BYTES).expect("replace empty fixture bytes");
	let page = job.open_checkpoint_page(ordinal).expect("reopen page");
	assert_read_only(&page);
	let mut observed = [0; BYTES.len()];
	page.read_exact_at(0, &mut observed).expect("read page");
	assert_eq!(&observed, BYTES);
}
