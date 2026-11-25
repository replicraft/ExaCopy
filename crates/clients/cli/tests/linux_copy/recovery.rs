use std::os::unix::fs::MetadataExt as _;

use super::{ChainHead, File, FrameKind, FrameReader};
use super::{Fixture, PROFILE, Path, Value, fs, job_directory, json};

#[test]
fn reports_current_receipt_and_detects_a_same_length_changed_target() {
	let fixture = Fixture::with_profile();
	fs::write(fixture.path("source"), b"owned data").expect("seed source");
	let published = fixture
		.copy("source", "target")
		.output()
		.expect("copy file");
	let job = job_directory(&fixture, &json(published, 0));

	let completed = inspect(&fixture, &job, PROFILE, 0);
	assert_eq!(completed["result"], "inspected");
	assert_eq!(completed["disposition"], "complete");
	assert_eq!(completed["journal_tail"], "clean");
	assert_eq!(completed["journal_sequence"], "9");

	fs::write(fixture.path("target"), b"alien data").expect("update target fixture");
	let observed = inspect(&fixture, &job, PROFILE, 9);
	assert_eq!(observed["disposition"], "requires_reconciliation");
	assert_eq!(observed["issue"], "stream_mismatch");
	assert_eq!(fs::read(fixture.path("target")).unwrap(), b"alien data");
	assert_eq!(fs::read(fixture.path("source")).unwrap(), b"owned data");
}

#[test]
fn a_different_profile_cannot_authenticate_a_retained_job() {
	let fixture = Fixture::with_profile();
	fs::write(fixture.path("source"), b"owned data").expect("seed source");
	let published = fixture
		.copy("source", "target")
		.output()
		.expect("copy file");
	let job = job_directory(&fixture, &json(published, 0));
	let initialized = fixture
		.command()
		.args(["profile", "init", "different"])
		.output()
		.expect("initialize an independent synthetic profile");
	assert!(initialized.status.success());

	let rejected = inspect(&fixture, &job, "different", 8);
	assert_eq!(rejected["result"], "failed");
	assert_eq!(rejected["code"], "E_PROFILE_AUTHORIZATION");
	assert_eq!(
		inspect(&fixture, &job, PROFILE, 0)["disposition"],
		"complete"
	);
}

#[test]
fn finishes_a_published_copy_without_replacing_the_target() {
	let fixture = Fixture::with_profile();
	fs::write(fixture.path("source"), b"owned data").expect("seed source");
	let published = fixture
		.copy("source", "target")
		.output()
		.expect("copy file");
	let job = job_directory(&fixture, &json(published, 0));
	let target = fixture.path("target");
	let inode = fs::metadata(&target).unwrap().ino();

	let journal = job.join("journal/00000000000000000001.exajnl");
	let mut reader = FrameReader::new(File::open(&journal).unwrap(), ChainHead::start());
	loop {
		if reader.next_frame().unwrap().unwrap().kind() == FrameKind::PublishIntent {
			break;
		}
	}
	fs::OpenOptions::new()
		.write(true)
		.open(&journal)
		.unwrap()
		.set_len(reader.offset())
		.expect("simulate stop after rename before its outcome");
	fs::remove_file(job.join("receipts/receipt.cbor")).expect("remove subsequent fixture receipt");
	assert_eq!(
		inspect(&fixture, &job, PROFILE, 9)["disposition"],
		"published_needs_barriers"
	);

	let result = recovery("finish", &fixture, &job, PROFILE, 0);
	assert_eq!(result["disposition"], "complete");
	assert_eq!(result["journal_sequence"], "11");
	assert_eq!(fs::metadata(&target).unwrap().ino(), inode);
	assert_eq!(fs::read(&target).unwrap(), b"owned data");
	let first = fs::read(&journal).unwrap();
	assert_eq!(recovery("finish", &fixture, &job, PROFILE, 0), result);
	assert_eq!(fs::read(&journal).unwrap(), first);
}

fn inspect(fixture: &Fixture, job: &Path, profile: &str, expected_exit: i32) -> Value {
	recovery("inspect", fixture, job, profile, expected_exit)
}

fn recovery(
	action: &str,
	fixture: &Fixture,
	job: &Path,
	profile: &str,
	expected_exit: i32,
) -> Value {
	let output = fixture
		.command()
		.args(["recover", action])
		.arg(job)
		.args(["--profile", profile, "--format", "json"])
		.output()
		.expect("inspect a retained job");
	assert_eq!(output.status.code(), Some(expected_exit), "{output:?}");
	assert!(output.stderr.is_empty());
	let report: Value = serde_json::from_slice(&output.stdout).expect("decode report");
	assert_eq!(report["schema"], "exacopy.local_recovery_inspection");
	report
}
