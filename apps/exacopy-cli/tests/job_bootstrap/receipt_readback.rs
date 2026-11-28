use std::cell::RefCell;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;

use exacopy_cli::assembly::linux::plan_new_file;
use exacopy_journal::{LinuxFileIdentity, ReceiptCommitted, ReceiptDigest};
use exacopy_platform::linux::{ReadRoot, StageError};
use exacopy_transfer::linux::{CopyCheckpoint, CopyError, CopyReceipt, copy_with_capabilities};

use super::{
	ChainHead, DestinationFixture, FIRST_SEGMENT, File, FrameKind, FrameReader, JOB_DIRECTORY,
	JOURNAL, TARGET, UnixComponent, copy_attempt, copy_profile, copy_roots, fixture_signer, fs,
	native_identity,
};

const SOURCE: &str = "source";
const SOURCE_BYTES: &[u8] = b"fixture-owned source survives receipt readback faults";
const RECEIPT: &str = "receipts/receipt.cbor";

thread_local! {
	static CONTROL: RefCell<Option<Rebind>> = const { RefCell::new(None) };
}

struct Rebind {
	at: CopyCheckpoint,
	selected: PathBuf,
	retained: PathBuf,
	target: PathBuf,
	observed: Option<Rebound>,
}

struct Rebound {
	receipt_bytes: Vec<u8>,
	original_receipt: LinuxFileIdentity,
	rebound_receipt: LinuxFileIdentity,
	published: LinuxFileIdentity,
}

#[test]
fn copy_refuses_a_same_byte_receipt_rebind_without_altering_the_public_result() {
	for (phase, terminal) in [
		(CopyCheckpoint::ReceiptSynced, FrameKind::DurabilityRecorded),
		(
			CopyCheckpoint::ReceiptCommitted,
			FrameKind::ReceiptCommitted,
		),
	] {
		check_receipt_rebind(phase, terminal);
	}
}

fn check_receipt_rebind(at: CopyCheckpoint, terminal: FrameKind) {
	let fixture = DestinationFixture::new();
	let source_path = fixture.path(SOURCE);
	fs::write(&source_path, SOURCE_BYTES).unwrap();
	let source_identity = native_identity(&fs::symlink_metadata(&source_path).unwrap());
	let source = ReadRoot::from_directory(File::open(&fixture.0).unwrap()).unwrap();
	let destination = fixture.open_root();
	let roots = copy_roots(&source, &destination);
	let plan = plan_new_file(
		roots,
		copy_attempt(),
		UnixComponent::new(SOURCE.as_bytes()).unwrap(),
		UnixComponent::new(TARGET.as_bytes()).unwrap(),
	)
	.unwrap();
	let job = fixture.path(JOB_DIRECTORY);
	assert!(CONTROL.with(|control| {
		control
			.replace(Some(Rebind {
				at,
				selected: job.join(RECEIPT),
				retained: job.join("receipts/retained-original"),
				target: fixture.path(TARGET),
				observed: None,
			}))
			.is_none()
	}));
	let signer = fixture_signer();
	let result = copy_with_capabilities(
		roots,
		&plan,
		copy_profile(&signer),
		&mut [0; 31],
		rebind_at_checkpoint,
	);
	let Rebind {
		selected,
		retained,
		target,
		observed,
		..
	} = CONTROL.with(|control| control.take().unwrap());
	assert!(matches!(
		result,
		Err(CopyError::ReceiptNamespace(StageError::IdentityChanged))
	));
	let observed = observed.expect("copy reached the selected receipt boundary");
	assert_ne!(observed.original_receipt, observed.rebound_receipt);
	assert_eq!(
		native_identity(&fs::symlink_metadata(&retained).unwrap()),
		observed.original_receipt
	);
	assert_eq!(
		native_identity(&fs::symlink_metadata(&selected).unwrap()),
		observed.rebound_receipt
	);
	assert_eq!(fs::read(retained).unwrap(), observed.receipt_bytes);
	assert_eq!(fs::read(selected).unwrap(), observed.receipt_bytes);
	assert_eq!(
		native_identity(&fs::symlink_metadata(&target).unwrap()),
		observed.published
	);
	assert_eq!(fs::read(target).unwrap(), SOURCE_BYTES);
	assert_eq!(
		native_identity(&fs::symlink_metadata(&source_path).unwrap()),
		source_identity
	);
	assert_eq!(fs::read(source_path).unwrap(), SOURCE_BYTES);

	let journal = File::open(job.join(JOURNAL).join(FIRST_SEGMENT)).unwrap();
	let mut reader = FrameReader::new(journal, ChainHead::start());
	let mut last = reader.next_frame().unwrap().unwrap();
	while let Some(frame) = reader.next_frame().unwrap() {
		last = frame;
	}
	assert_eq!(last.kind(), terminal);
	if terminal == FrameKind::ReceiptCommitted {
		let receipt = CopyReceipt::decode(&observed.receipt_bytes).unwrap();
		let committed = ReceiptCommitted::from_frame(&last).unwrap();
		assert_eq!(
			committed.digest(),
			ReceiptDigest::from_bytes(receipt.digest())
		);
	}
}

fn rebind_at_checkpoint(phase: CopyCheckpoint) {
	CONTROL.with(|control| {
		let mut control = control.borrow_mut();
		let selected = control.as_mut().unwrap();
		if selected.at != phase {
			return;
		}
		assert!(selected.observed.is_none());
		let receipt_bytes = fs::read(&selected.selected).unwrap();
		let published = native_identity(&fs::symlink_metadata(&selected.target).unwrap());
		let original_receipt = native_identity(&fs::symlink_metadata(&selected.selected).unwrap());
		// Deliberately violate cooperation inside this owned disposable fixture.
		fs::rename(&selected.selected, &selected.retained).unwrap();
		OpenOptions::new()
			.write(true)
			.create_new(true)
			.mode(0o600)
			.open(&selected.selected)
			.unwrap()
			.write_all(&receipt_bytes)
			.unwrap();
		let rebound_receipt = native_identity(&fs::symlink_metadata(&selected.selected).unwrap());
		selected.observed = Some(Rebound {
			receipt_bytes,
			original_receipt,
			rebound_receipt,
			published,
		});
	});
}
