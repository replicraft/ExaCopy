use std::cell::RefCell;
use std::fs::OpenOptions;
use std::io::Read as _;
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use exacopy_cli::assembly::linux::plan_new_file;
use exacopy_journal::frame::{FrameProblem, FrameReadError};
use exacopy_journal::{DurableJournalError, LinuxFileIdentity, ReceiptCommitted, ReceiptDigest};
use exacopy_platform::linux::ReadRoot;
use exacopy_transfer::linux::{CopyCheckpoint, CopyError, CopyReceipt, copy_with_capabilities};
use rustix::fs::OFlags;

use super::{
	ChainHead, DestinationFixture, FIRST_SEGMENT, File, FrameKind, FrameReader, JOB_DIRECTORY,
	JOURNAL, STAGE, TARGET, UnixComponent, assert_absent, copy_attempt, copy_profile, copy_roots,
	fixture_signer, fs, native_identity,
};

const DATA: &[u8] = b"fixture source remains after terminal journal readback refusal";
const MAX_CONTROL_JOURNAL_BYTES: u64 = 16 * 1024;

thread_local! {
	static CONTROL: RefCell<Option<Control>> = const { RefCell::new(None) };
}

struct Control {
	segment: PathBuf,
	receipt: PathBuf,
	target: PathBuf,
	fault: Option<Fault>,
}

struct Fault {
	segment: LinuxFileIdentity,
	receipt: LinuxFileIdentity,
	target: LinuxFileIdentity,
	bad_segment_bytes: Vec<u8>,
	receipt_bytes: Vec<u8>,
}

#[test]
fn copy_refuses_a_corrupt_prefix_after_receipt_commitment_and_preserves_publication() {
	let fixture = DestinationFixture::new();
	let source_path = fixture.path("source");
	fs::write(&source_path, DATA).unwrap();
	let source_identity = identity(&source_path);
	let source = ReadRoot::from_directory(File::open(&fixture.0).unwrap()).unwrap();
	let destination = fixture.open_root();
	let roots = copy_roots(&source, &destination);
	let attempt = copy_attempt();
	let plan = plan_new_file(
		roots,
		attempt,
		UnixComponent::new(b"source").unwrap(),
		UnixComponent::new(TARGET.as_bytes()).unwrap(),
	)
	.unwrap();

	let job = fixture.path(JOB_DIRECTORY);
	assert!(CONTROL.with(|control| {
		control
			.replace(Some(Control {
				segment: job.join(JOURNAL).join(FIRST_SEGMENT),
				receipt: job.join("receipts/receipt.cbor"),
				target: fixture.path(TARGET),
				fault: None,
			}))
			.is_none()
	}));
	let signer = fixture_signer();
	let result = copy_with_capabilities(
		roots,
		&plan,
		copy_profile(&signer),
		&mut [0; 29],
		fault_after_commitment,
	);
	let control = CONTROL.with(|control| control.take().unwrap());
	assert!(matches!(
		result,
		Err(CopyError::ReceiptJournalReadback(
			DurableJournalError::ReadFrame(FrameReadError::Corrupt {
				offset: 0,
				problem: FrameProblem::Magic,
			})
		))
	));
	let fault = control
		.fault
		.expect("copy reached the post-commitment fault");
	assert_eq!(identity(&control.segment), fault.segment);
	assert_eq!(
		read_journal(&File::open(&control.segment).unwrap()),
		fault.bad_segment_bytes
	);
	assert_eq!(identity(&control.receipt), fault.receipt);
	assert_eq!(fs::read(&control.receipt).unwrap(), fault.receipt_bytes);
	assert_eq!(identity(&control.target), fault.target);
	assert_eq!(fs::read(&control.target).unwrap(), DATA);
	assert_eq!(identity(&source_path), source_identity);
	assert_eq!(fs::read(source_path).unwrap(), DATA);
	assert_absent(&job.join(STAGE).join("payload"));
}

fn fault_after_commitment(phase: CopyCheckpoint) {
	if phase != CopyCheckpoint::ReceiptCommitted {
		return;
	}
	CONTROL.with(|control| {
		let mut control = control.borrow_mut();
		let control = control.as_mut().unwrap();
		assert!(control.fault.is_none());
		let journal = OpenOptions::new()
			.read(true)
			.write(true)
			.custom_flags(i32::try_from((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits()).unwrap())
			.open(&control.segment)
			.unwrap();
		let stat = journal.metadata().unwrap();
		assert!(stat.is_file());
		let segment = native_identity(&stat);
		assert_eq!(segment, identity(&control.segment));
		let mut bytes = read_journal(&journal);
		let receipt_bytes = fs::read(&control.receipt).unwrap();
		let receipt = CopyReceipt::decode(&receipt_bytes).unwrap();
		let target = identity(&control.target);
		assert_eq!(receipt.evidence().stream.identity, target);
		let mut reader = FrameReader::new(bytes.as_slice(), ChainHead::start());
		let mut last = reader.next_frame().unwrap().unwrap();
		assert_eq!(last.kind(), FrameKind::JobPrepared);
		while let Some(frame) = reader.next_frame().unwrap() {
			last = frame;
		}
		assert_eq!(last.kind(), FrameKind::ReceiptCommitted);
		assert_eq!(
			ReceiptCommitted::from_frame(&last).unwrap().digest(),
			ReceiptDigest::from_bytes(receipt.digest())
		);
		// Deliberately break cooperation inside this owned fixture. Only an early
		// magic byte changes. The segment identity, extent and kind-18 bytes persist.
		bytes[0] ^= 1;
		journal.write_all_at(&bytes[..1], 0).unwrap();
		control.fault = Some(Fault {
			segment,
			receipt: identity(&control.receipt),
			target,
			bad_segment_bytes: bytes,
			receipt_bytes,
		});
	});
}

fn read_journal(file: &File) -> Vec<u8> {
	let mut bytes = Vec::new();
	file.take(MAX_CONTROL_JOURNAL_BYTES + 1)
		.read_to_end(&mut bytes)
		.unwrap();
	assert!(u64::try_from(bytes.len()).unwrap() <= MAX_CONTROL_JOURNAL_BYTES);
	bytes
}

fn identity(path: &Path) -> LinuxFileIdentity {
	let metadata = fs::symlink_metadata(path).unwrap();
	assert!(metadata.is_file());
	native_identity(&metadata)
}
