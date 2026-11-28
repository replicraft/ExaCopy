use std::cell::{Cell, RefCell};
use std::fs::{self, FileTimes, OpenOptions};
use std::io;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::time::Duration;

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_apply::{ApplyRole, ApplyStep, GuardedCopyJob, LocalApplyAdmission};
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

#[test]
fn guarded_receipt_accepts_the_exact_extent_in_file_then_parent_order() {
	use ApplyRole::{Job, Receipt, ReceiptDirectory};
	use ApplyStep::{Create, Sync, Write};

	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let job = root.create_job_directory(job_name()).unwrap();
	let directory = fixture.path(JOB).join(RECEIPTS);
	let gate = ReceiptGate::new(|_| {});
	for bytes in [&[][..], &[0; RECEIPT_CAP + 1][..]] {
		assert!(matches!(
			job.seal_fresh_receipt_admitted(bytes, &gate),
			Err(FreshReceiptError::Namespace(StageError::InvalidLength))
		));
		assert!(gate.steps.borrow().is_empty());
		assert!(!directory.try_exists().unwrap());
	}

	let mut expected = [0x65; RECEIPT_CAP];
	expected[0] = 0x08;
	expected[RECEIPT_CAP - 1] = 0xf3;
	let held = job.seal_fresh_receipt_admitted(&expected, &gate).unwrap();
	let steps = gate.steps.borrow();
	let [
		Create(ReceiptDirectory),
		Create(Receipt),
		writes @ ..,
		Sync(Receipt),
		Sync(ReceiptDirectory),
		Sync(Job),
	] = steps.as_slice()
	else {
		panic!("unexpected receipt effect order: {steps:?}");
	};
	// Each retry reenters admission for the same approved window.
	assert!(!writes.is_empty());
	assert!(
		writes
			.iter()
			.all(|step| *step == Write(Receipt, 0, RECEIPT_CAP))
	);

	let path = directory.join(RECEIPT);
	let stat = held.file.metadata().unwrap();
	assert_eq!((stat.dev(), stat.ino()), identity(&path));
	let mut observed = [SENTINEL; RECEIPT_CAP];
	held.read_exact_receipt(&mut observed).unwrap();
	assert_eq!(observed, expected);
	assert_eq!(
		held.file
			.read_at(&mut [0], u64::try_from(RECEIPT_CAP).unwrap())
			.unwrap(),
		0
	);
	assert_eq!(fs::read(path).unwrap(), expected);
}

#[test]
fn guarded_receipt_refuses_same_bytes_rebound_at_file_barrier() {
	use ApplyRole::{Receipt, ReceiptDirectory};
	use ApplyStep::{Create, Sync, Write};

	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let job = root.create_job_directory(job_name()).unwrap();
	let directory = fixture.path(JOB).join(RECEIPTS);
	let selected = directory.join(RECEIPT);
	let retained = directory.join("original-receipt");

	let source = fixture.path("source");
	let incumbent = fixture.path("incumbent");
	write_new(&source, b"source outside receipt workspace");
	write_new(&incumbent, b"incumbent outside receipt workspace");
	let before = [identity(&source), identity(&incumbent)];
	let original = Cell::new(None);
	let gate = ReceiptGate::new(|step| {
		if step == Sync(Receipt) {
			// Deliberately rebind only our own receipt in the fixture.
			original.set(Some(identity(&selected)));
			fs::rename(&selected, &retained).unwrap();
			write_new(&selected, RECEIPT_BYTES);
		}
	});
	assert!(matches!(
		job.seal_fresh_receipt_admitted(RECEIPT_BYTES, &gate),
		Err(FreshReceiptError::Namespace(StageError::IdentityChanged))
	));
	let steps = gate.steps.borrow();
	let [
		Create(ReceiptDirectory),
		Create(Receipt),
		writes @ ..,
		Sync(Receipt),
	] = steps.as_slice()
	else {
		panic!("unexpected receipt effect order: {steps:?}");
	};
	assert!(!writes.is_empty());
	assert!(
		writes
			.iter()
			.all(|step| *step == Write(Receipt, 0, RECEIPT_BYTES.len()))
	);

	assert_eq!(Some(identity(&retained)), original.get());
	assert_ne!(Some(identity(&selected)), original.get());
	assert_eq!(fs::read(&retained).unwrap(), RECEIPT_BYTES);
	assert_eq!(fs::read(&selected).unwrap(), RECEIPT_BYTES);
	assert_eq!([identity(&source), identity(&incumbent)], before);
	assert_eq!(
		fs::read(source).unwrap(),
		b"source outside receipt workspace"
	);
	assert_eq!(
		fs::read(incumbent).unwrap(),
		b"incumbent outside receipt workspace"
	);
}

#[test]
fn guarded_receipt_refuses_changed_original_with_unchanged_extent_at_file_barrier() {
	use ApplyRole::{Job, Receipt, ReceiptDirectory};
	use ApplyStep::Sync;

	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).unwrap();
	let job = root.create_job_directory(job_name()).unwrap();
	let path = fixture.path(JOB).join(RECEIPTS).join(RECEIPT);
	let expected = b"complete original record";
	let changed = b"modified original record";
	assert_eq!(expected.len(), changed.len());
	let original = Cell::new(None);
	let gate = ReceiptGate::new(|step| {
		if step == Sync(Receipt) {
			original.set(Some(identity(&path)));
			let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
			let before = writer.metadata().unwrap().modified().unwrap();
			writer.write_all(changed).unwrap();
			let modified = before.checked_add(Duration::from_secs(1)).unwrap();
			writer
				.set_times(FileTimes::new().set_modified(modified))
				.unwrap();
			assert_ne!(writer.metadata().unwrap().modified().unwrap(), before);
		}
	});
	assert!(matches!(
		job.seal_fresh_receipt_admitted(expected, &gate),
		Err(FreshReceiptError::Namespace(StageError::ReadBack(
			ReadError::SourceChanged
		)))
	));
	let steps = gate.steps.borrow();
	assert_eq!(steps.last(), Some(&Sync(Receipt)));
	assert!(!steps.contains(&Sync(ReceiptDirectory)));
	assert!(!steps.contains(&Sync(Job)));
	assert_eq!(Some(identity(&path)), original.get());
	assert_eq!(fs::read(path).unwrap(), changed);
}

fn write_new(path: &Path, bytes: &[u8]) {
	OpenOptions::new()
		.create_new(true)
		.write(true)
		.mode(0o600)
		.open(path)
		.unwrap()
		.write_all(bytes)
		.unwrap();
}

struct ReceiptGate<F> {
	steps: RefCell<Vec<ApplyStep>>,
	on_enter: F,
}

impl<F: Fn(ApplyStep)> ReceiptGate<F> {
	fn new(on_enter: F) -> Self {
		Self {
			steps: RefCell::default(),
			on_enter,
		}
	}
}

impl<F: Fn(ApplyStep)> LocalApplyAdmission for ReceiptGate<F> {
	type Guard<'gate>
		= ()
	where
		Self: 'gate;

	fn enter(&self, step: ApplyStep) -> io::Result<()> {
		self.steps.borrow_mut().push(step);
		(self.on_enter)(step);
		Ok(())
	}
}

fn identity(path: &Path) -> (u64, u64) {
	let metadata = fs::symlink_metadata(path).unwrap();
	(metadata.dev(), metadata.ino())
}

fn job_name() -> UnixComponent<'static> {
	UnixComponent::new(JOB.as_bytes()).unwrap()
}
