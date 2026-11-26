//! Native CLI checks for single-subject read-only synchronization preview.
#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::DirBuilderExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;

const TEST_PARENT: &str = "/dev/shm";
const EXCESS_FILE_BYTES: u64 = 64 * 1024 * 1024 + 1;
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
	fn new() -> Self {
		let case = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
		let path =
			Path::new(TEST_PARENT).join(format!("exacopy-preview-{}-{case}", std::process::id()));
		fs::DirBuilder::new()
			.mode(0o700)
			.create(&path)
			.expect("create private test scope on Linux tmpfs");
		let fixture = Self(path);
		fs::create_dir(fixture.0.join("left")).unwrap();
		fs::create_dir(fixture.0.join("right")).unwrap();
		fixture
	}

	fn command(&self, subject: &OsStr) -> Command {
		let mut command = Command::new(env!("CARGO_BIN_EXE_exacopy"));
		command
			.arg("sync-preview")
			.arg(&self.0)
			.args(["left", "right"])
			.arg(subject);
		command
	}

	fn preview(&self, subject: &OsStr, exit: i32) -> Value {
		let output = self.command(subject).arg("--no-history").output().unwrap();
		assert_eq!(output.status.code(), Some(exit), "{output:?}");
		serde_json::from_slice(&output.stdout).unwrap()
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		fs::remove_dir_all(&self.0).unwrap();
	}
}

#[test]
fn exact_raw_scope_reports_conflicts_equality_and_one_sided_candidate() {
	let fixture = Fixture::new();
	let subject = OsStr::from_bytes(b"file-\xff");
	let left = fixture.0.join("left").join(subject);
	let right = fixture.0.join("right").join(subject);
	fs::write(&left, b"one").unwrap();
	fs::write(&right, b"two").unwrap();
	let report = fixture.preview(subject, 3);
	assert_eq!(report["status"], "conflict");
	assert_eq!(report["reason"], "divergent_versions");
	assert_eq!(report["left"]["state"], "present");
	assert_eq!(report["selection"]["subject_hex"], "66696c652dff");
	assert_eq!(report["right"]["bytes"], 3);
	assert_ne!(
		report["left"]["stream_digest"],
		report["right"]["stream_digest"]
	);
	assert_eq!(fs::read(&left).unwrap(), b"one");
	assert_eq!(fs::read(&right).unwrap(), b"two");

	fs::write(&right, b"one").unwrap();
	let report = fixture.preview(subject, 0);
	assert_eq!(report["status"], "matching_observations");
	assert_eq!(report["history"], "none");
	assert_eq!(report["left"], report["right"]);

	fs::set_permissions(&right, fs::Permissions::from_mode(0o400)).unwrap();
	let report = fixture.preview(subject, 3);
	assert_eq!(report["reason"], "divergent_versions");
	assert_eq!(
		report["left"]["stream_digest"],
		report["right"]["stream_digest"]
	);
	assert_ne!(
		report["left"]["required_metadata_digest"],
		report["right"]["required_metadata_digest"]
	);

	fs::remove_file(&right).unwrap();
	let report = fixture.preview(subject, 0);
	assert_eq!(report["status"], "copy_candidate");
	assert_eq!(report["from"], "left");
	assert_eq!(report["right"]["state"], "absent_observed");
	assert!(!right.exists(), "preview never creates the candidate");
	assert_eq!(fs::read(&left).unwrap(), b"one");
}

#[test]
fn oversized_or_unavailable_scope_blocks_without_a_candidate() {
	let fixture = Fixture::new();
	let subject = OsStr::new("file");
	let file = fs::File::create(fixture.0.join("right/file")).unwrap();
	file.set_len(EXCESS_FILE_BYTES).unwrap();
	let report = fixture.preview(subject, 2);
	assert_eq!(report["status"], "blocked");
	assert_eq!(report["reason"], "resource_limit");
	assert_eq!(report["side"], "right");
	assert!(report.get("from").is_none());

	fs::rename(fixture.0.join("left"), fixture.0.join("old-left")).unwrap();
	let report = fixture.preview(subject, 2);
	assert_eq!(report["reason"], "unknown_observation");
	assert!(report.get("right").is_none());
	assert_eq!(file.metadata().unwrap().len(), EXCESS_FILE_BYTES);
}

#[test]
fn cli_requires_explicit_no_history_and_rejects_mutation_options() {
	let fixture = Fixture::new();
	let subject = OsStr::new("file");
	for options in [&[][..], &["--no-history", "--apply"][..]] {
		let output = fixture.command(subject).args(options).output().unwrap();
		assert_eq!(output.status.code(), Some(2), "{output:?}");
		assert!(output.stdout.is_empty());
	}
}
