use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::Path;

use exacopy_endpoint::UnixComponent;

use super::{
	DATA, FINAL, FIRST_SEGMENT, Fixture, JOB, JOURNAL, JOURNAL_BYTES, JobFileIdentity, PENDING,
	RECEIPT_BYTES, STAGE, STAGE_NAME, StageError, TARGET, WITNESS, WitnessedTerminalSelection,
	identity, write_fixture,
};
use crate::linux::ReadError;

#[test]
fn terminal_inventory_refuses_inconsistent_terminal_selection() {
	let fixture = Fixture::new();
	let selection = fixture.selection();
	let job = fixture
		.root
		.open_recovery_job(UnixComponent::new(JOB.as_bytes()).unwrap())
		.unwrap();
	let lease = job.try_read_lease().unwrap();
	let records = lease.hold_witnessed_terminal_journal().unwrap();
	records.inspect(selection).unwrap().recheck().unwrap();

	let mut mismatched_pending_name = *PENDING;
	*mismatched_pending_name.last_mut().unwrap() = b'1';
	let invalid_names = WitnessedTerminalSelection {
		pending_name: mismatched_pending_name,
		..selection
	};
	let wrong_journal_end = WitnessedTerminalSelection {
		journal_end: 0,
		..selection
	};
	let receipt_alias = WitnessedTerminalSelection {
		receipt: selection.stage.file,
		..selection
	};
	for (label, rejected) in [
		(
			"pending receipt nonce differs from its final name",
			invalid_names,
		),
		(
			"journal end differs from the held extent",
			wrong_journal_end,
		),
		("receipt aliases the published stage", receipt_alias),
	] {
		assert!(
			matches!(records.inspect(rejected), Err(StageError::IdentityChanged)),
			"{label}"
		);
	}
	records.inspect(selection).unwrap().recheck().unwrap();
	assert_file(&fixture.scratch.path(TARGET), selection.stage.file, DATA);
	assert_file(&fixture.path(WITNESS), selection.stage.file, DATA);
	assert_file(&fixture.path(FINAL), selection.receipt, RECEIPT_BYTES);
	assert_missing(&fixture.path(PENDING));
	assert_missing(&fixture.scratch.path(JOB).join(STAGE).join(STAGE_NAME));
}

#[test]
fn terminal_inventory_refuses_same_bytes_at_a_rebound_receipt_name() {
	let fixture = Fixture::new();
	let selection = fixture.selection();
	let job = fixture
		.root
		.open_recovery_job(UnixComponent::new(JOB.as_bytes()).unwrap())
		.unwrap();
	let lease = job.try_read_lease().unwrap();
	let records = lease.hold_witnessed_terminal_journal().unwrap();
	let artifacts = records.inspect(selection).unwrap();

	let receipt = fixture.path(FINAL);
	let original = fixture.path(b"retained-original-receipt");
	fs::rename(&receipt, &original).unwrap();
	write_fixture(&receipt, RECEIPT_BYTES);
	let replacement = identity(&receipt);
	assert_ne!(replacement, selection.receipt);
	assert!(matches!(
		records.inspect(selection),
		Err(StageError::IdentityChanged)
	));
	assert!(matches!(
		artifacts.recheck(),
		Err(StageError::IdentityChanged)
	));
	assert_file(&receipt, replacement, RECEIPT_BYTES);
	assert_file(&original, selection.receipt, RECEIPT_BYTES);
	assert_file(&fixture.scratch.path(TARGET), selection.stage.file, DATA);
	assert_file(&fixture.path(WITNESS), selection.stage.file, DATA);
	assert_missing(&fixture.path(PENDING));
	assert_missing(&fixture.scratch.path(JOB).join(STAGE).join(STAGE_NAME));
}

#[test]
fn terminal_inventory_refuses_occupied_pending_and_private_stage_names() {
	let fixture = Fixture::new();
	let selection = fixture.selection();
	let job = fixture
		.root
		.open_recovery_job(UnixComponent::new(JOB.as_bytes()).unwrap())
		.unwrap();
	let lease = job.try_read_lease().unwrap();
	let records = lease.hold_witnessed_terminal_journal().unwrap();
	let source = fixture.scratch.path("source");
	let pending = fixture.path(PENDING);
	let stage = fixture.scratch.path(JOB).join(STAGE).join(STAGE_NAME);
	let source_bytes = b"separate source bytes";
	let pending_bytes = b"unexpected pending receipt";
	let stage_bytes = b"unexpected private stage";
	write_fixture(&source, source_bytes);
	write_fixture(&pending, pending_bytes);
	let source_id = identity(&source);
	let pending_id = identity(&pending);

	assert!(matches!(
		records.inspect(selection),
		Err(StageError::IdentityChanged)
	));
	assert_file(&pending, pending_id, pending_bytes);

	let retained_pending = fixture.path(b"retained-pending");
	fs::rename(&pending, &retained_pending).unwrap();
	write_fixture(&stage, stage_bytes);
	let stage_id = identity(&stage);
	assert!(matches!(
		records.inspect(selection),
		Err(StageError::IdentityChanged)
	));
	assert_file(&source, source_id, source_bytes);
	assert_file(&stage, stage_id, stage_bytes);
	assert_file(&retained_pending, pending_id, pending_bytes);
	assert_file(&fixture.scratch.path(TARGET), selection.stage.file, DATA);
	assert_file(&fixture.path(WITNESS), selection.stage.file, DATA);
	assert_file(&fixture.path(FINAL), selection.receipt, RECEIPT_BYTES);
	assert_missing(&pending);
}

#[test]
fn terminal_journal_holder_refuses_missing_and_empty_segment() {
	let fixture = Fixture::new();
	let job = fixture
		.root
		.open_recovery_job(UnixComponent::new(JOB.as_bytes()).unwrap())
		.unwrap();
	let lease = job.try_read_lease().unwrap();
	let journal = fixture.scratch.path(JOB).join(JOURNAL).join(FIRST_SEGMENT);
	let original = fixture.path(b"retained-original-segment");
	let original_id = identity(&journal);
	fs::rename(&journal, &original).unwrap();

	assert!(matches!(
		lease.hold_witnessed_terminal_journal(),
		Err(StageError::IdentityChanged)
	));
	assert_missing(&journal);
	write_fixture(&journal, b"");
	let empty_id = identity(&journal);
	assert!(matches!(
		lease.hold_witnessed_terminal_journal(),
		Err(StageError::IdentityChanged)
	));
	assert_file(&journal, empty_id, b"");
	assert_file(&original, original_id, JOURNAL_BYTES);
}

#[test]
fn terminal_journal_reader_refuses_data_beyond_captured_extent() {
	let fixture = Fixture::new();
	let job = fixture
		.root
		.open_recovery_job(UnixComponent::new(JOB.as_bytes()).unwrap())
		.unwrap();
	let lease = job.try_read_lease().unwrap();
	let records = lease.hold_witnessed_terminal_journal().unwrap();
	let mut reader = records.journal();
	let mut prefix = [0; JOURNAL_BYTES.len()];
	reader.read_exact(&mut prefix).unwrap();
	assert_eq!(prefix, JOURNAL_BYTES);

	let journal = fixture.scratch.path(JOB).join(JOURNAL).join(FIRST_SEGMENT);
	let journal_id = identity(&journal);
	OpenOptions::new()
		.append(true)
		.open(&journal)
		.unwrap()
		.write_all(b" extra bytes")
		.unwrap();

	let mut beyond_end = [0];
	let error = reader.read(&mut beyond_end).unwrap_err();
	assert!(matches!(
		error
			.get_ref()
			.and_then(|cause| cause.downcast_ref::<ReadError>()),
		Some(ReadError::UnexpectedDataAfterEnd)
	));
	assert_eq!(beyond_end, [0]);
	let expected = [JOURNAL_BYTES, b" extra bytes"].concat();
	assert_file(&journal, journal_id, &expected);
}

fn assert_file(path: &Path, expected_identity: JobFileIdentity, expected_bytes: &[u8]) {
	assert_eq!(identity(path), expected_identity, "identity of {path:?}");
	assert_eq!(fs::read(path).unwrap(), expected_bytes, "bytes of {path:?}");
}

fn assert_missing(path: &Path) {
	assert!(
		matches!(
			fs::symlink_metadata(path),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound
		),
		"expected absent name at {path:?}"
	);
}

#[test]
fn committed_receipt_refuses_pending_name_before_invalid_public_artifacts() {
	let fixture = Fixture::new();
	let selection = fixture.selection();
	let job = fixture
		.root
		.open_recovery_job(UnixComponent::new(JOB.as_bytes()).unwrap())
		.unwrap();
	let lease = job.try_read_lease().unwrap();
	let records = lease.hold_witnessed_terminal_journal().unwrap();
	let pending = fixture.path(PENDING);
	let extra = fixture.scratch.path("third-public-link");
	write_fixture(&pending, b"unexpected pending receipt");
	let pending_id = identity(&pending);
	fs::hard_link(fixture.scratch.path(TARGET), &extra).unwrap();

	assert!(matches!(
		records.inspect_receipt_ready(selection),
		Err(StageError::UnsafeFile)
	));
	assert!(matches!(
		records.inspect(selection),
		Err(StageError::IdentityChanged)
	));
	assert_file(&pending, pending_id, b"unexpected pending receipt");
	assert_file(&fixture.scratch.path(TARGET), selection.stage.file, DATA);
	assert_file(&fixture.path(WITNESS), selection.stage.file, DATA);
	assert_file(&extra, selection.stage.file, DATA);
	assert_file(&fixture.path(FINAL), selection.receipt, RECEIPT_BYTES);
}
