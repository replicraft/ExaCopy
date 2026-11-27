use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use exacopy_endpoint::UnixComponent;

use super::{
	FIRST_SEGMENT, JOURNAL, JobFileIdentity, OWNER, RetainedPrefixSelection, StageError,
	WitnessedPublishedSelection, WitnessedTerminalSelection,
};
use crate::linux::DestinationRoot;
use crate::linux::job::STAGE;
use crate::scratch::Scratch;

#[path = "../../../../tests/unit/linux/recovery/terminal.rs"]
mod refusal_tests;

const JOB: &str = "terminal-job";
const TARGET: &str = "target";
const STAGE_NAME: &str = "old-stage";
const WITNESS: &[u8; 40] = b"witness.1112131415161718191a1b1c1d1e1f20";
const PENDING: &[u8; 101] =
	b"rw-receipt.pending.0102030405060708090a0b0c0d0e0f10.0000000000000001.1112131415161718191a1b1c1d1e1f20";
const FINAL: &[u8; 99] =
	b"rw-receipt.final.0102030405060708090a0b0c0d0e0f10.0000000000000001.1112131415161718191a1b1c1d1e1f20";
const OWNER_BYTES: &[u8] = b"literal owner";
const JOURNAL_BYTES: &[u8] = b"literal journal";
const DATA: &[u8] = b"two read-only aliases";
const RECEIPT_BYTES: &[u8] = b"literal receipt";

struct Fixture {
	scratch: Scratch,
	root: DestinationRoot,
}

impl Fixture {
	fn new() -> Self {
		let scratch = Scratch::new();
		let root = DestinationRoot::from_directory(scratch.open()).unwrap();
		let job = scratch.path(JOB);
		for path in [&job, &job.join(STAGE), &job.join(JOURNAL)] {
			DirBuilder::new().mode(0o700).create(path).unwrap();
		}
		write_fixture(&job.join(OWNER), OWNER_BYTES);
		write_fixture(&job.join(JOURNAL).join(FIRST_SEGMENT), JOURNAL_BYTES);
		write_fixture(&scratch.path(TARGET), DATA);
		fs::hard_link(scratch.path(TARGET), job.join(text(WITNESS))).unwrap();
		write_fixture(&job.join(text(FINAL)), RECEIPT_BYTES);
		Self { scratch, root }
	}

	fn selection(&self) -> WitnessedTerminalSelection<'static> {
		let job = self.scratch.path(JOB);
		let target = self.scratch.path(TARGET);
		let metadata = fs::metadata(&target).unwrap();
		WitnessedTerminalSelection {
			job: identity(&job),
			destination: self.root.identity().into(),
			stage: RetainedPrefixSelection {
				stage: UnixComponent::new(STAGE_NAME.as_bytes()).unwrap(),
				target: UnixComponent::new(TARGET.as_bytes()).unwrap(),
				directory: identity(&job.join(STAGE)),
				file: identity(&target),
			},
			witness_name: *WITNESS,
			pending_name: *PENDING,
			final_name: *FINAL,
			uid: metadata.uid(),
			gid: metadata.gid(),
			extent: DATA.len() as u64,
			receipt: identity(&job.join(text(FINAL))),
			receipt_len: u16::try_from(RECEIPT_BYTES.len()).unwrap(),
			journal_end: JOURNAL_BYTES.len() as u64,
		}
	}

	fn path(&self, name: &[u8]) -> PathBuf {
		self.scratch.path(JOB).join(text(name))
	}
}

#[test]
fn terminal_inventory_pins_exact_records_and_refuses_late_pending_name() {
	let fixture = Fixture::new();
	let selection = fixture.selection();
	let job_name = UnixComponent::new(JOB.as_bytes()).unwrap();
	let job = fixture.root.open_recovery_job(job_name).unwrap();
	let lease = job.try_read_lease().unwrap();
	let records = lease.hold_witnessed_terminal_journal().unwrap();
	assert!(matches!(
		fixture
			.root
			.try_recovery_write_lease(job_name, job.identity()),
		Err(StageError::JobBusy)
	));
	let mut owner = [0; OWNER_BYTES.len()];
	records.owner().read_exact_at(0, &mut owner).unwrap();
	assert_eq!(owner, OWNER_BYTES);
	let mut cursor = records.journal();
	let mut data = Vec::new();
	cursor.read_to_end(&mut data).unwrap();
	assert_eq!(data, JOURNAL_BYTES);
	assert_eq!(records.segment_length(), selection.journal_end);

	let held = records.inspect(selection).unwrap();
	assert_eq!(
		JobFileIdentity::from(held.target().identity()),
		selection.stage.file
	);
	assert_eq!(
		JobFileIdentity::from(held.receipt().identity()),
		selection.receipt
	);
	assert_eq!(held.target().observation().link_count(), 2);
	assert_eq!(held.receipt().observation().link_count(), 1);
	let mut exact = [0; RECEIPT_BYTES.len()];
	held.receipt().read_exact_at(0, &mut exact).unwrap();
	assert_eq!(exact, RECEIPT_BYTES);
	held.recheck().unwrap();

	write_fixture(&fixture.path(PENDING), b"unselected pending artifact");
	assert!(matches!(held.recheck(), Err(StageError::IdentityChanged)));
	assert_eq!(
		fs::read(fixture.path(PENDING)).unwrap(),
		b"unselected pending artifact"
	);
}

#[test]
fn terminal_inventory_refuses_changed_journal_and_foreign_witness_inode() {
	let fixture = Fixture::new();
	let selection = fixture.selection();
	let job = fixture
		.root
		.open_recovery_job(UnixComponent::new(JOB.as_bytes()).unwrap())
		.unwrap();
	let lease = job.try_read_lease().unwrap();
	let records = lease.hold_witnessed_terminal_journal().unwrap();
	let witness = fixture.path(WITNESS);
	// Same bytes and same link-count shape, with a different inode.
	fs::remove_file(&witness).unwrap();
	write_fixture(&witness, DATA);
	fs::hard_link(&witness, fixture.path(b"foreign-witness-link")).unwrap();
	fs::hard_link(
		fixture.scratch.path(TARGET),
		fixture.path(b"foreign-target-link"),
	)
	.unwrap();
	assert!(matches!(
		records.inspect(selection),
		Err(StageError::IdentityChanged)
	));

	let journal = fixture.scratch.path(JOB).join(JOURNAL).join(FIRST_SEGMENT);
	fs::rename(&journal, fixture.path(b"original-segment")).unwrap();
	write_fixture(&journal, JOURNAL_BYTES);
	assert!(records.recheck().is_err());
}

#[test]
fn witnessed_public_assessment_checks_two_aliases_without_using_receipt_names() {
	let fixture = Fixture::new();
	let selection = fixture.selection();
	let job = fixture
		.root
		.open_recovery_job(UnixComponent::new(JOB.as_bytes()).unwrap())
		.unwrap();
	let lease = job.try_read_lease().unwrap();
	let records = lease.hold_witnessed_terminal_journal().unwrap();
	let expected = WitnessedPublishedSelection {
		job: selection.job,
		destination: selection.destination,
		stage: selection.stage,
		witness_name: selection.witness_name,
		uid: selection.uid,
		gid: selection.gid,
		extent: selection.extent,
		journal_end: selection.journal_end,
	};
	let wrong_stage_directory = WitnessedPublishedSelection {
		stage: RetainedPrefixSelection {
			directory: selection.job,
			..selection.stage
		},
		..expected
	};
	assert!(matches!(
		records.inspect_published(wrong_stage_directory),
		Err(StageError::IdentityChanged)
	));
	let malformed_witness = WitnessedPublishedSelection {
		witness_name: *b"witness.1112131415161718191a1b1c1d1e1f2G",
		..expected
	};
	assert!(matches!(
		records.inspect_published(malformed_witness),
		Err(StageError::IdentityChanged)
	));
	let receipt = fixture.path(FINAL);
	fs::remove_file(&receipt).unwrap();
	let read = records.inspect_published(expected).unwrap();
	let mut data = [0; DATA.len()];
	read.target().read_exact_at(0, &mut data).unwrap();
	assert_eq!(data, DATA);
	assert!(matches!(
		records.inspect(selection),
		Err(StageError::IdentityChanged)
	));

	let extra_link = fixture.path(b"unexpected-third-link");
	fs::hard_link(fixture.scratch.path(TARGET), &extra_link).unwrap();
	assert!(matches!(read.recheck(), Err(StageError::UnsafeFile)));
	assert!(matches!(
		records.inspect_published(expected),
		Err(StageError::UnsafeFile)
	));
	assert_eq!(fs::read(&extra_link).unwrap(), DATA);
	assert_eq!(fs::read(fixture.path(WITNESS)).unwrap(), DATA);
	fs::remove_file(&extra_link).unwrap();
	let read = records.inspect_published(expected).unwrap();

	let former_private_stage = fixture.scratch.path(JOB).join(STAGE).join(STAGE_NAME);
	write_fixture(&former_private_stage, b"unexpected private stage bytes");
	assert!(read.recheck().is_err());
	assert_eq!(
		fs::read(former_private_stage).unwrap(),
		b"unexpected private stage bytes"
	);
	assert!(!receipt.exists());
}

fn write_fixture(path: &Path, bytes: &[u8]) {
	OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(path)
		.unwrap()
		.write_all(bytes)
		.unwrap();
}

fn identity(path: &Path) -> JobFileIdentity {
	let metadata = fs::metadata(path).unwrap();
	JobFileIdentity {
		device: metadata.dev(),
		inode: metadata.ino(),
	}
}

fn text(bytes: &[u8]) -> &str {
	std::str::from_utf8(bytes).unwrap()
}
