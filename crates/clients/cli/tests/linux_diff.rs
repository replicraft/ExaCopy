//! Process-level tests for the Linux exact comparison route.
#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::fs::{self, DirBuilder};
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, symlink};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;

#[test]
fn equal_bytes_with_raw_filename_produce_a_structured_live_result() {
	let fixture = Fixture::new();
	let raw = OsStr::from_bytes(b"raw\xff\nfile");
	fs::write(fixture.0.join(raw), b"equal\x00data").expect("write raw filename");
	fs::create_dir(fixture.0.join("nested")).expect("create nested directory");
	let right = fixture.0.join("nested/right");
	fs::write(&right, b"equal\x00data").expect("write right file");

	let output = fixture
		.diff(raw, &right)
		.args(["--compare", "bytes", "--format", "json"])
		.output()
		.expect("invoke diff");
	let report = read_json(output, 0);
	assert_eq!(report["result"], "equal");
	assert_eq!(report["complete"], true);
	assert_eq!(report["consistency"], "live_observed");
	assert_eq!(report["length"], "10");
}

#[test]
fn same_length_and_different_length_comparisons_use_exit_one() {
	let fixture = Fixture::new();
	fs::write(fixture.0.join("left"), b"abc").expect("write left file");
	let right = fixture.0.join("right");
	fs::write(&right, b"abd").expect("write same-length right file");
	let output = fixture
		.diff("left", "right")
		.args(["--format", "json"])
		.output()
		.expect("invoke diff");
	let report = read_json(output, 1);
	assert_eq!(report["result"], "different");
	assert_eq!(report["complete"], true);
	assert_eq!(report["consistency"], "live_observed");
	assert_eq!(report["difference"]["kind"], "first_byte");
	assert_eq!(report["difference"]["offset"], "2");

	fs::write(right, b"ab").expect("write shorter right file");
	let human = fixture
		.diff("left", "right")
		.output()
		.expect("invoke human diff");
	assert_eq!(human.status.code(), Some(1));
	assert!(human.stderr.is_empty());
	let summary = String::from_utf8(human.stdout).expect("read human result");
	assert!(summary.contains("Different lengths (left 3 bytes, right 2 bytes, live_observed)."));
}

#[test]
fn refused_inputs_are_inconclusive_and_the_original_input_remains_intact() {
	let fixture = Fixture::new();
	let original = fixture.0.join("left");
	fs::write(&original, b"source").expect("write left file");
	symlink("left", fixture.0.join("link")).expect("create final symlink");
	for (input, error_code) in [
		("missing", "E_OPEN_INPUT"),
		("link", "E_OPEN_INPUT"),
		("left/", "E_INVALID_PATH"),
		("left/.", "E_INVALID_PATH"),
		("", "E_INVALID_PATH"),
		("/proc/version", "E_COMPARE_INPUT"),
	] {
		let output = fixture
			.diff("left", input)
			.args(["--format", "json"])
			.output()
			.expect("invoke diff");
		let report = read_json(output, 2);
		assert_eq!(report["result"], "inconclusive", "{input}");
		assert_eq!(report["complete"], false, "{input}");
		assert_eq!(report["error"]["code"], error_code, "{input}");
		assert!(report.get("consistency").is_none(), "{input}");
	}
	assert_eq!(
		fs::read(original).expect("read original fixture"),
		b"source"
	);
}

#[test]
fn an_open_failure_reports_on_stderr_in_human_mode() {
	let fixture = Fixture::new();
	fs::write(fixture.0.join("left"), b"source").expect("write left file");
	let output = fixture
		.diff("left", "missing")
		.output()
		.expect("invoke diff");
	assert_eq!(output.status.code(), Some(2));
	assert!(output.stdout.is_empty());
	let diagnostic = String::from_utf8(output.stderr).expect("read diagnostic");
	assert!(diagnostic.contains("comparison inconclusive"));
	assert!(diagnostic.contains("right input file"));
	assert!(!diagnostic.contains("missing"));
}

fn read_json(output: Output, exit: i32) -> Value {
	assert_eq!(
		output.status.code(),
		Some(exit),
		"stderr: {:?}",
		String::from_utf8_lossy(&output.stderr),
	);
	assert!(output.stderr.is_empty());
	let report: Value = serde_json::from_slice(&output.stdout).expect("read one JSON report");
	assert_eq!(report["schema"], "exacopy.cli.diff");
	assert_eq!(report["schema_version"], "1.0");
	assert_eq!(report["relation"], "bytes");
	report
}

struct Fixture(PathBuf);

impl Fixture {
	fn new() -> Self {
		static NEXT: AtomicUsize = AtomicUsize::new(0);
		const MAX_ATTEMPTS: usize = 128;
		const PRIVATE_MODE: u32 = 0o700;

		for _ in 0..MAX_ATTEMPTS {
			let token = NEXT.fetch_add(1, Ordering::Relaxed);
			let path = std::env::temp_dir()
				.join(format!("exacopy-cli-tests-{}-{token}", std::process::id()));
			match DirBuilder::new().mode(PRIVATE_MODE).create(&path) {
				Ok(()) => return Self(path),
				Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
				Err(error) => panic!("create fixture directory: {error}"),
			}
		}
		panic!("exhausted synthetic fixture directory attempts");
	}

	fn diff(&self, left: impl AsRef<OsStr>, right: impl AsRef<OsStr>) -> Command {
		let mut command = Command::new(env!("CARGO_BIN_EXE_exacopy"));
		command
			.current_dir(&self.0)
			.arg("diff")
			.arg(left)
			.arg(right);
		command
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}
