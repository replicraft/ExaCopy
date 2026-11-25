use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use exacopy_journal::frame::{ChainHead, FrameKind, FrameReader};
use serde_json::Value;

use super::{Fixture, PROFILE, job_directory, json};

const SOURCE_ROOT: &str = "private-source";
const TARGET: &str = "target";
const DATA: &[u8] = b"owned data";

#[test]
fn retries_a_retained_inode_and_repeats_without_changing_the_receipt() {
	let retained = Retained::new();
	let stage_inode = fs::metadata(retained.stage()).unwrap().ino();
	let accepted_prefix = fs::read(retained.journal()).unwrap();

	let first = retained.retry(SOURCE_ROOT, 0);
	assert_eq!(first["result"], "inspected");
	assert_eq!(first["disposition"], "complete");
	assert_eq!(first["journal_tail"], "clean");
	let target = retained.fixture.path(TARGET);
	assert_eq!(fs::metadata(&target).unwrap().ino(), stage_inode);
	assert_eq!(fs::read(&target).unwrap(), DATA);
	assert_eq!(fs::read(retained.source()).unwrap(), DATA);
	assert!(!retained.stage().exists());

	let journal = fs::read(retained.journal()).unwrap();
	assert!(journal.starts_with(&accepted_prefix));
	assert!(journal.len() > accepted_prefix.len());
	let receipt = fs::read(retained.receipt()).unwrap();
	assert_eq!(retained.retry(SOURCE_ROOT, 0), first);
	assert_eq!(fs::read(retained.journal()).unwrap(), journal);
	assert_eq!(fs::read(retained.receipt()).unwrap(), receipt);
}

#[test]
fn resume_leaves_an_active_intent_for_explicit_retry() {
	let retained = Retained::new();
	let stage_inode = fs::metadata(retained.stage()).unwrap().ino();
	let initial_journal = fs::read(retained.journal()).unwrap();

	let result = retained.recover("resume", SOURCE_ROOT, 9);
	assert_eq!(result["disposition"], "possible_retry");
	assert_eq!(result["journal_tail"], "clean");
	assert_eq!(fs::read(retained.journal()).unwrap(), initial_journal);
	assert_eq!(fs::metadata(retained.stage()).unwrap().ino(), stage_inode);
	assert!(!retained.fixture.path(TARGET).exists());
	assert!(!retained.receipt().exists());

	assert_eq!(retained.retry(SOURCE_ROOT, 0)["disposition"], "complete");
	assert_eq!(fs::read(retained.fixture.path(TARGET)).unwrap(), DATA);
}

#[test]
fn rejects_wrong_source_grants_and_changed_source_bytes_without_leaking_paths() {
	let retained = Retained::new();
	let journal = fs::read(retained.journal()).unwrap();

	let wrong_root = retained.retry(".", 5);
	assert_eq!(wrong_root["result"], "failed");
	assert_eq!(wrong_root["code"], "E_SOURCE_MISMATCH");

	fs::write(retained.source(), b"alien data").expect("change source with same length");
	let changed_source = retained.retry(SOURCE_ROOT, 5);
	assert_eq!(changed_source["code"], "E_SOURCE_MISMATCH");
	assert!(!changed_source.to_string().contains(SOURCE_ROOT));
	assert!(!changed_source.to_string().contains("raw-source"));
	assert_eq!(fs::read(retained.journal()).unwrap(), journal);
	assert_eq!(fs::read(retained.source()).unwrap(), b"alien data");
	assert_eq!(fs::read(retained.stage()).unwrap(), DATA);
	assert!(!retained.fixture.path(TARGET).exists());
	assert!(!retained.receipt().exists());
}

#[test]
fn reports_conflict_and_preserves_both_inodes() {
	let retained = Retained::new();
	let target = retained.fixture.path(TARGET);
	fs::write(&target, b"incumbent").expect("seed incumbent target");
	let incumbent = fs::metadata(&target).unwrap().ino();
	let journal = fs::read(retained.journal()).unwrap();

	let result = retained.retry(SOURCE_ROOT, 3);
	assert_eq!(result["disposition"], "conflict");
	assert_eq!(fs::metadata(&target).unwrap().ino(), incumbent);
	assert_eq!(fs::read(&target).unwrap(), b"incumbent");
	assert_eq!(fs::read(retained.source()).unwrap(), DATA);
	assert_eq!(fs::read(retained.stage()).unwrap(), DATA);
	assert_eq!(fs::read(retained.journal()).unwrap(), journal);
	assert!(!retained.receipt().exists());
}

#[test]
fn reports_reconciliation_for_a_torn_journal_without_publication() {
	let retained = Retained::cut_after_intent(1);
	let journal = fs::read(retained.journal()).unwrap();

	let result = retained.retry(SOURCE_ROOT, 9);
	assert_eq!(result["disposition"], "requires_reconciliation");
	assert_eq!(result["journal_tail"], "torn");
	assert_eq!(result["issue"], "torn_journal");
	assert_eq!(fs::read(retained.journal()).unwrap(), journal);
	assert_eq!(fs::read(retained.stage()).unwrap(), DATA);
	assert!(!retained.fixture.path(TARGET).exists());
}

struct Retained {
	fixture: Fixture,
	job: PathBuf,
}

impl Retained {
	fn new() -> Self {
		Self::cut_after_intent(0)
	}

	fn cut_after_intent(torn_bytes: u64) -> Self {
		let fixture = Fixture::with_profile();
		fs::create_dir(fixture.path(SOURCE_ROOT)).expect("make distinct source root");
		fs::write(fixture.path(source_path()), DATA).expect("seed synthetic source");
		let published = fixture
			.copy(source_path(), TARGET)
			.output()
			.expect("copy source");
		let job = job_directory(&fixture, &json(published, 0));
		let retained = Self { fixture, job };
		fs::rename(retained.fixture.path(TARGET), retained.stage())
			.expect("reconstruct stage and absent target before publication");
		fs::remove_file(retained.receipt()).expect("remove later fixture receipt");
		let journal = retained.journal();
		let mut reader = FrameReader::new(File::open(&journal).unwrap(), ChainHead::start());
		loop {
			if reader.next_frame().unwrap().unwrap().kind() == FrameKind::PublishIntent {
				break;
			}
		}
		fs::OpenOptions::new()
			.write(true)
			.open(journal)
			.unwrap()
			.set_len(reader.offset() + torn_bytes)
			.expect("keep the journal through the first intent");
		retained
	}

	fn source(&self) -> PathBuf {
		self.fixture.path(source_path())
	}

	fn stage(&self) -> PathBuf {
		self.job.join("stage/data")
	}

	fn receipt(&self) -> PathBuf {
		self.job.join("receipts/receipt.cbor")
	}

	fn journal(&self) -> PathBuf {
		self.job.join("journal/00000000000000000001.exajnl")
	}

	fn retry(&self, source_root: &str, exit: i32) -> Value {
		self.recover("retry", source_root, exit)
	}

	fn recover(&self, action: &str, source_root: &str, exit: i32) -> Value {
		let output = self
			.fixture
			.command()
			.args(["recover", action])
			.arg(&self.job)
			.args([
				"--source-root",
				source_root,
				"--profile",
				PROFILE,
				"--format",
				"json",
			])
			.output()
			.expect("recover a retained job");
		assert_eq!(output.status.code(), Some(exit), "{output:?}");
		assert!(output.stderr.is_empty());
		let report: Value = serde_json::from_slice(&output.stdout).expect("decode report");
		assert_eq!(report["schema"], "exacopy.local_recovery_inspection");
		assert_eq!(report["schema_version"], "1.0");
		report
	}
}

fn source_path() -> PathBuf {
	Path::new(SOURCE_ROOT).join(OsStr::from_bytes(b"raw-source-\xff"))
}
