use std::fs::{self, OpenOptions};
use std::io::{Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::Path;

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_publication::{
	FreshReceiptError, FreshReceiptWorkspace, HeldFreshReceipt,
};
use rustix::fs::{OFlags, fcntl_getfl};
use rustix::io::{Errno, FdFlags, fcntl_getfd};

use crate::linux::job::{RECEIPT, RECEIPTS};
use crate::linux::{DestinationRoot, ReadError, StageError};
use crate::scratch::Scratch;

const JOB: &str = "fresh-receipt-job";
const RECEIPT_CAP: usize = 1024;
const SENTINEL: u8 = 0x5a;
const RECEIPT_BYTES: &[u8] = b"fixed artifact under the leased job";

#[test]
fn fresh_receipt_reads_the_named_inode_through_eof_without_write_access() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let job = root.create_job_directory(job_name()).unwrap();
	let mut expected = [0x63; RECEIPT_CAP];
	expected[0] = 0x10;
	expected[RECEIPT_CAP - 1] = 0xef;
	let held = job.seal_fresh_receipt(&expected).unwrap();
	let path = fixture.path(JOB).join(RECEIPTS).join(RECEIPT);
	let named = fs::symlink_metadata(&path).unwrap();
	let opened = held.file.metadata().unwrap();
	assert!(named.is_file() && opened.is_file());
	assert_eq!((named.dev(), named.ino()), (opened.dev(), opened.ino()));

	let flags = fcntl_getfl(&held.file).unwrap();
	assert_eq!(flags & OFlags::ACCMODE, OFlags::RDONLY);
	assert!(!flags.contains(OFlags::PATH));
	assert!(fcntl_getfd(&held.file).unwrap().contains(FdFlags::CLOEXEC));
	let refused_write = held.file.write_at(b"!", 0).unwrap_err();
	assert_eq!(
		refused_write.raw_os_error(),
		Some(Errno::BADF.raw_os_error())
	);

	let inspection = root.open_recovery_job(job_name()).unwrap();
	assert!(matches!(
		inspection.try_read_lease(),
		Err(StageError::JobBusy)
	));
	let mut cursor = &held.file;
	assert_eq!(cursor.stream_position().unwrap(), 0);
	assert_eq!(cursor.seek(SeekFrom::Start(17)).unwrap(), 17);
	let mut observed = [SENTINEL; RECEIPT_CAP];
	held.read_exact_receipt(&mut observed).unwrap();
	assert_eq!(observed, expected);
	assert_eq!(cursor.stream_position().unwrap(), 17);
	assert_eq!(
		held.file
			.read_at(&mut [0], u64::try_from(expected.len()).unwrap())
			.unwrap(),
		0
	);
	assert_eq!(fs::read(path).unwrap(), expected);
}

#[test]
fn receipt_length_refusals_leave_names_artifact_and_output_untouched() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let job = root.create_job_directory(job_name()).unwrap();
	let directory = fixture.path(JOB).join(RECEIPTS);
	for invalid in [&[][..], &[0; RECEIPT_CAP + 1][..]] {
		assert!(matches!(
			job.seal_fresh_receipt(invalid),
			Err(FreshReceiptError::Namespace(StageError::InvalidLength))
		));
		assert!(!directory.try_exists().unwrap());
	}

	let held = job.seal_fresh_receipt(RECEIPT_BYTES).unwrap();
	let path = directory.join(RECEIPT);
	let original = identity(&path);
	let mut wrong_extent = [SENTINEL; RECEIPT_BYTES.len() - 1];
	let mut over_cap = [SENTINEL; RECEIPT_CAP + 1];
	for output in [&mut wrong_extent[..], &mut over_cap[..]] {
		assert!(matches!(
			held.read_exact_receipt(output),
			Err(StageError::InvalidLength)
		));
		assert!(output.iter().all(|byte| *byte == SENTINEL));
	}
	let mut observed = [0; RECEIPT_BYTES.len()];
	held.read_exact_receipt(&mut observed).unwrap();
	assert_eq!(observed, RECEIPT_BYTES);
	assert_eq!(identity(&path), original);
	assert_eq!(fs::read(&path).unwrap(), RECEIPT_BYTES);
}

#[test]
fn receipt_read_refuses_a_grown_original_before_consuming_output() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let job = root.create_job_directory(job_name()).unwrap();
	let held = job.seal_fresh_receipt(RECEIPT_BYTES).unwrap();
	let path = fixture.path(JOB).join(RECEIPTS).join(RECEIPT);
	let original = identity(&path);

	// Deliberate same-principal fixture fault. The expected bytes remain a prefix.
	OpenOptions::new()
		.append(true)
		.open(&path)
		.unwrap()
		.write_all(b"!")
		.unwrap();
	let mut output = [SENTINEL; RECEIPT_BYTES.len()];
	assert!(matches!(
		held.read_exact_receipt(&mut output),
		Err(StageError::ReadBack(ReadError::SourceChanged))
	));
	assert_eq!(output, [SENTINEL; RECEIPT_BYTES.len()]);
	assert_eq!(identity(&path), original);
	assert_eq!(fs::read(path).unwrap(), [RECEIPT_BYTES, b"!"].concat());
}

#[test]
fn receipt_read_refuses_a_rebound_parent_with_identical_artifact_bytes() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let job = root.create_job_directory(job_name()).unwrap();
	let held = job.seal_fresh_receipt(RECEIPT_BYTES).unwrap();
	let selected = fixture.path(JOB).join(RECEIPTS);
	let retained = fixture.path("retained-receipts");
	let original_directory = identity(&selected);
	let original_receipt = identity(&selected.join(RECEIPT));

	// Deliberately substitute our own receipt directory while the original is held.
	fs::rename(&selected, &retained).unwrap();
	let replacement = job.create_receipt_directory().unwrap();
	replacement
		.create_receipt_record()
		.unwrap()
		.write_all(RECEIPT_BYTES)
		.unwrap();
	let replacement_directory = identity(&selected);
	let replacement_receipt = identity(&selected.join(RECEIPT));
	assert_ne!(replacement_directory, original_directory);
	assert_ne!(replacement_receipt, original_receipt);

	let mut output = [SENTINEL; RECEIPT_BYTES.len()];
	assert!(matches!(
		held.read_exact_receipt(&mut output),
		Err(StageError::IdentityChanged)
	));
	assert_eq!(output, [SENTINEL; RECEIPT_BYTES.len()]);
	assert_eq!(identity(&retained), original_directory);
	assert_eq!(identity(&retained.join(RECEIPT)), original_receipt);
	assert_eq!(identity(&selected), replacement_directory);
	assert_eq!(identity(&selected.join(RECEIPT)), replacement_receipt);
	assert_eq!(fs::read(retained.join(RECEIPT)).unwrap(), RECEIPT_BYTES);
	assert_eq!(fs::read(selected.join(RECEIPT)).unwrap(), RECEIPT_BYTES);
}

fn identity(path: &Path) -> (u64, u64) {
	let metadata = fs::symlink_metadata(path).unwrap();
	(metadata.dev(), metadata.ino())
}

fn job_name() -> UnixComponent<'static> {
	UnixComponent::new(JOB.as_bytes()).unwrap()
}
