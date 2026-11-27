use std::fs::{self, File};
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;

use exacopy_endpoint::IoError;
use exacopy_endpoint::linux_publication::{
	ExclusivePublication, PublicationFailure, ReceiptDirectory as ReceiptDirectoryCapability,
	ReceiptRecord, ReceiptWorkspace,
};
use exacopy_model::{CopyBinding, EntryId, JobId, RunEpoch, StageId};

use super::{PublishError, authorization, component};
use crate::linux::{DestinationRoot, ReadRoot, StageError, TargetStatus};
use crate::scratch::Scratch;

#[test]
fn publication_capability_keeps_late_incumbent_source_and_private_stage() {
	const SOURCE: &str = "source";
	const STAGE_DIR: &str = "stage";
	const PART: &str = "part";
	const TARGET: &str = "target";
	const SOURCE_BYTES: &[u8] = b"payload!";
	const INCUMBENT: &[u8] = b"existing";

	let fixture = Scratch::new();
	let source_path = fixture.path(SOURCE);
	fs::write(&source_path, SOURCE_BYTES).expect("seed source");
	let sources = ReadRoot::from_directory(fixture.open()).expect("held source scope");
	let source = sources
		.open_regular(component(SOURCE))
		.expect("read-only source");
	let mut source_bytes = [0; SOURCE_BYTES.len()];
	source
		.read_exact_at(0, &mut source_bytes)
		.expect("read exact source stream");
	assert_eq!(&source_bytes, SOURCE_BYTES);

	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination scope");
	assert!(matches!(
		root.target_status(component(TARGET)),
		Ok(TargetStatus::Absent)
	));
	let directory = root
		.create_stage_directory(component(STAGE_DIR))
		.expect("private stage directory");
	let job = JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
		.expect("fixture job is UUIDv7");
	let binding = CopyBinding::new(
		job,
		EntryId::new(1),
		RunEpoch::new(2),
		StageId::from_bytes([1; 16]),
	);
	let mut writer = directory
		.create_file(component(PART), component(TARGET), binding)
		.expect("new private file");
	writer
		.write_all_at(0, &source_bytes)
		.expect("stage source data");
	writer.flush().expect("file barrier");
	let stage = writer.close_writes().expect("join the stage writer");
	let mut read_back = [0; SOURCE_BYTES.len()];
	stage
		.read_exact_at(0, &mut read_back)
		.expect("verify independent stage read-back");
	assert_eq!(read_back, source_bytes);
	let mut outside = [0xa5; 1];
	for offset in [stage.length(), u64::MAX] {
		assert!(matches!(
			stage.read_exact_at(offset, &mut outside),
			Err(IoError::InvalidRange { offset: rejected, length: 1 })
				if rejected == offset
		));
		assert_eq!(outside, [0xa5], "refused read must leave the buffer intact");
	}
	let stage = stage
		.apply_metadata(source.observation())
		.expect("apply and verify required metadata");
	let stage_identity = stage.identity();
	assert_ne!(stage_identity, source.identity());

	let target = fixture.path(TARGET);
	fs::write(&target, INCUMBENT).expect("arrive after the absence observation");
	let incumbent_identity = file_identity(&File::open(&target).expect("hold incumbent"));
	let model_token = authorization(binding);
	assert!(matches!(
		ExclusivePublication::publish_no_clobber(stage, model_token),
		Err(PublicationFailure::Conflict(PublishError::Conflict))
	));

	let private = fixture.path(STAGE_DIR).join(PART);
	let private_file = File::open(&private).expect("private stage still named");
	assert_eq!(
		file_identity(&private_file),
		(stage_identity.device(), stage_identity.inode())
	);
	assert_eq!(
		file_identity(&File::open(&target).expect("incumbent still named")),
		incumbent_identity
	);
	assert_eq!(
		file_identity(&File::open(&source_path).expect("source still named")),
		(source.identity().device(), source.identity().inode())
	);
	source
		.recheck_observation()
		.expect("held source observation remains current");
	assert_eq!(
		fs::read(&private).expect("retain stage bytes"),
		source_bytes
	);
	assert_eq!(
		fs::read(&target).expect("retain incumbent bytes"),
		INCUMBENT
	);
	assert_eq!(
		fs::read(&source_path).expect("retain source bytes"),
		source_bytes
	);
}

#[test]
fn publication_capability_projects_a_stale_epoch_as_unconfirmed() {
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination scope");
	let directory = root
		.create_stage_directory(component("stage"))
		.expect("private stage directory");
	let job = JobId::try_from_bytes([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1])
		.expect("fixture job is UUIDv7");
	let binding = |epoch| {
		CopyBinding::new(
			job,
			EntryId::new(1),
			RunEpoch::new(epoch),
			StageId::from_bytes([1; 16]),
		)
	};
	let mut writer = directory
		.create_file(component("part"), component("target"), binding(2))
		.expect("new private file");
	writer
		.write_all_at(0, b"private bytes")
		.expect("write stage");
	writer.flush().expect("file barrier");
	let stage = writer.close_writes().expect("join the stage writer");
	assert!(matches!(
		ExclusivePublication::publish_no_clobber(stage, authorization(binding(1))),
		Err(PublicationFailure::Uncertain(PublishError::BindingMismatch))
	));
	assert!(matches!(
		root.target_status(component("target")),
		Ok(TargetStatus::Absent)
	));
	assert_eq!(
		fs::read(fixture.path("stage").join("part")).expect("retain private stage"),
		b"private bytes"
	);
}

#[test]
fn receipt_capability_syncs_one_private_record_and_refuses_recreation() {
	const JOB: &str = "job";
	const PAYLOAD: &[u8] = b"fixture receipt bytes";
	let fixture = Scratch::new();
	let root = DestinationRoot::from_directory(fixture.open()).expect("held destination scope");
	let job = root
		.create_job_directory(component(JOB))
		.expect("private job directory");
	let receipts =
		ReceiptWorkspace::create_receipt_directory(&job).expect("create receipt directory");
	let mut record = ReceiptDirectoryCapability::create_receipt_record(&receipts)
		.expect("create receipt record");
	record.write_all(PAYLOAD).expect("write receipt");
	record.flush().expect("flush receipt writer");
	ReceiptRecord::sync_all(&record).expect("receipt file barrier");
	ReceiptDirectoryCapability::sync_directory(&receipts).expect("receipt directory barrier");
	ReceiptWorkspace::sync_directory(&job).expect("job directory barrier");
	drop(record);

	let path = fixture.path(JOB).join("receipts").join("receipt.cbor");
	let original = File::open(&path).expect("hold original receipt inode");
	let attributes = original.metadata().expect("inspect receipt permissions");
	assert_eq!(attributes.mode() & 0o7777, 0o600);
	assert_eq!(attributes.nlink(), 1);
	assert!(matches!(
		ReceiptWorkspace::create_receipt_directory(&job),
		Err(StageError::AlreadyExists)
	));
	assert!(matches!(
		ReceiptDirectoryCapability::create_receipt_record(&receipts),
		Err(StageError::AlreadyExists)
	));
	assert_eq!(
		file_identity(&File::open(&path).expect("receipt still named")),
		file_identity(&original)
	);
	assert_eq!(fs::read(path).expect("read retained receipt"), PAYLOAD);
}

fn file_identity(file: &File) -> (u64, u64) {
	let metadata = file.metadata().expect("inspect held file identity");
	assert!(metadata.is_file());
	(metadata.dev(), metadata.ino())
}
