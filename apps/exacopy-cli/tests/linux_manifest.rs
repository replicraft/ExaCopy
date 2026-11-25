//! Linux process coverage for creating a public baseline and verifying against it.
#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::fs::{self, DirBuilder};
use std::io::ErrorKind;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use rustix::io::Errno;
use serde_json::{Value, json};

const SOURCE: &str = "source.bin";
const BASELINE: &str = "baseline.json";
const ABC_DIGEST: &str = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85";

#[test]
fn creates_and_verifies_raw_basename_without_a_profile() {
	const RAW_NAME: &[u8] = b"-raw-\xff-\x1b[31m.bin";
	const RAW_BASE64: &str = "LXJhdy3/LRtbMzFtLmJpbg==";

	let fixture = Fixture::new();
	let name = OsStr::from_bytes(RAW_NAME);
	let source = fixture.0.join(name);
	fs::write(&source, b"abc").unwrap();
	let source_identity = identity(&source);

	let baseline_bytes = fixture.create_baseline(name);
	let record: Value = serde_json::from_slice(&baseline_bytes).unwrap();
	let body = &record["body"];
	assert_eq!(body["schema_version"], "1.0");
	assert_eq!(body["algorithm"], "blake3-256");
	assert_eq!(body["consistency"], "live_observed");
	assert_eq!(body["complete"], true);
	let entry = &body["entries"][0];
	assert_eq!(
		entry["path"]["components"],
		json!([
			{"encoding": "unix_bytes", "raw_base64": RAW_BASE64}
		])
	);
	assert_eq!(entry["metadata_ref"], Value::Null);
	assert_eq!(
		entry["streams"],
		json!([{
			"name_raw_base64": "",
			"length": "3",
			"algorithm": "blake3-256",
			"digest": ABC_DIGEST
		}])
	);
	let baseline_path = fixture.0.join(BASELINE);
	let baseline_identity = identity(&baseline_path);
	let report = verify_report(fixture.verify(name, "json"), 0);
	assert_eq!(report["result"], "verified");
	assert_eq!(report["complete"], true);
	assert_eq!(report["length"], "3");
	assert_eq!(report["algorithm"], "blake3-256");
	assert_eq!(report["consistency"], "live_observed");
	assert_eq!(report["baseline_authentication"], "unsigned");
	assert_eq!(report["metadata"], "explicitly_omitted");

	let human = fixture.verify(name, "human");
	assert_exit(&human, 0);
	assert!(human.stderr.is_empty());
	assert!(
		human
			.stdout
			.starts_with(b"Verified 3 bytes against the unsigned BLAKE3 baseline")
	);
	assert!(!human.stdout.contains(&0x1b));
	assert!(
		!human
			.stdout
			.windows(RAW_NAME.len())
			.any(|window| window == RAW_NAME)
	);
	assert_preserved(&source, source_identity, b"abc");
	assert_preserved(&baseline_path, baseline_identity, &baseline_bytes);
	assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 2);
}

#[test]
fn verification_mismatches_report_completed_integrity_failures() {
	let fixture = Fixture::new();
	let name = OsStr::new(SOURCE);
	let source = fixture.0.join(name);
	fs::write(&source, b"abc").unwrap();
	let baseline_bytes = fixture.create_baseline(name);
	let baseline_path = fixture.0.join(BASELINE);
	let baseline_identity = identity(&baseline_path);

	fs::write(&source, b"abd").unwrap();
	let source_identity = identity(&source);
	let digest = verify_report(fixture.verify(name, "json"), 5);
	assert_eq!(digest["result"], "mismatch");
	assert_eq!(digest["complete"], true);
	assert_eq!(digest["length"], "3");
	assert_eq!(digest["difference"]["kind"], "digest");
	assert_eq!(digest["difference"]["expected"], ABC_DIGEST);
	assert_eq!(digest["difference"]["observed"].as_str().unwrap().len(), 64);
	assert_ne!(digest["difference"]["observed"], ABC_DIGEST);
	assert_preserved(&source, source_identity, b"abd");

	fs::write(&source, b"ab").unwrap();
	let length = verify_report(fixture.verify(name, "json"), 5);
	assert_eq!(length["result"], "mismatch");
	assert_eq!(length["complete"], true);
	assert_eq!(
		length["difference"],
		json!({
			"kind": "length",
			"expected": "3",
			"observed": "2"
		})
	);
	assert_eq!(length["length"], "2");
	assert_preserved(&source, source_identity, b"ab");
	assert_preserved(&baseline_path, baseline_identity, &baseline_bytes);
}

#[test]
fn validates_baseline_before_target_admission() {
	let fixture = Fixture::new();
	let name = OsStr::new(SOURCE);
	let source = fixture.0.join(name);
	let held = fixture.0.join("original.bin");
	let baseline_path = fixture.0.join(BASELINE);
	fs::write(&source, b"abc").unwrap();
	let baseline_bytes = fixture.create_baseline(name);
	let original_identity = identity(&source);
	fs::rename(&source, &held).unwrap();

	let missing = inconclusive(fixture.verify(name, "json"), 2, "E_INPUT_PATH");
	assert_eq!(
		missing["error"]["os_code"],
		Errno::NOENT.raw_os_error().to_string()
	);

	let record: Value = serde_json::from_slice(&baseline_bytes).unwrap();
	let mut corrupt = record.clone();
	corrupt["digest"] = json!("0".repeat(64));
	let corrupt = serde_json::to_vec(&corrupt).unwrap();
	fs::write(&baseline_path, &corrupt).unwrap();
	let corrupt_identity = identity(&baseline_path);
	let refusal = inconclusive(fixture.verify(name, "json"), 5, "E_MANIFEST_INTEGRITY");
	assert!(refusal["error"].get("os_code").is_none());
	assert_preserved(&baseline_path, corrupt_identity, &corrupt);

	fs::write(&baseline_path, b"{").unwrap();
	inconclusive(fixture.verify(name, "json"), 2, "E_MANIFEST_INVALID");

	let mut unsupported = record;
	unsupported["body"]["schema_version"] = json!("9.0");
	fs::write(&baseline_path, serde_json::to_vec(&unsupported).unwrap()).unwrap();
	inconclusive(fixture.verify(name, "json"), 6, "E_MANIFEST_UNSUPPORTED");

	fs::write(&baseline_path, &baseline_bytes).unwrap();
	symlink(&held, &source).unwrap();
	let unsupported = inconclusive(fixture.verify(name, "json"), 6, "E_MANIFEST_UNSUPPORTED");
	assert_eq!(
		unsupported["error"]["os_code"],
		Errno::LOOP.raw_os_error().to_string()
	);
	assert_eq!(fs::read_link(&source).unwrap(), held);
	assert_preserved(&held, original_identity, b"abc");
}

#[test]
fn verification_requires_a_baseline_and_checks_exact_basename() {
	let fixture = Fixture::new();
	fs::write(fixture.0.join(SOURCE), b"abc").unwrap();
	let output = fixture.command().args(["verify", SOURCE]).output().unwrap();
	assert_exit(&output, 2);
	assert!(output.stdout.is_empty());
	assert!(!output.stderr.is_empty());

	fixture.create_baseline(OsStr::new(SOURCE));
	let wrong_case = OsStr::new("Source.bin");
	fs::write(fixture.0.join(wrong_case), b"abc").unwrap();
	let scope = inconclusive(fixture.verify(wrong_case, "json"), 2, "E_MANIFEST_SCOPE");
	assert!(scope["error"].get("os_code").is_none());
}

#[test]
fn human_verification_does_not_follow_or_replay_manifest_display() {
	let fixture = Fixture::new();
	let name = OsStr::new(SOURCE);
	let source = fixture.0.join(name);
	let display_path = fixture.0.join("misleading\x1b[31m.bin");
	fs::write(&source, b"abc").unwrap();
	fs::write(&display_path, b"unselected data").unwrap();

	let mut record: Value = serde_json::from_slice(&fixture.create_baseline(name)).unwrap();
	record["body"]["entries"][0]["path"]["display"] = json!(display_path.to_str().unwrap());
	let baseline_bytes = serde_json::to_vec(&record).unwrap();
	let baseline_path = fixture.0.join(BASELINE);
	fs::write(&baseline_path, &baseline_bytes).unwrap();
	let baseline_identity = identity(&baseline_path);
	let selected_identity = identity(&source);
	let display_identity = identity(&display_path);

	let output = fixture.verify(name, "human");
	assert_exit(&output, 0);
	assert!(output.stderr.is_empty());
	let human = String::from_utf8(output.stdout).unwrap();
	assert!(human.starts_with("Verified 3 bytes"));
	assert!(!human.contains("misleading"));
	assert!(!human.contains('\x1b'));
	assert!(!human.contains(SOURCE));
	assert_preserved(&source, selected_identity, b"abc");
	assert_preserved(&display_path, display_identity, b"unselected data");
	assert_preserved(&baseline_path, baseline_identity, &baseline_bytes);
}

fn assert_exit(output: &Output, code: i32) {
	assert_eq!(output.status.code(), Some(code), "{output:?}");
}

fn verify_report(output: Output, code: i32) -> Value {
	assert_exit(&output, code);
	assert!(output.stderr.is_empty(), "{output:?}");
	let report: Value = serde_json::from_slice(&output.stdout).unwrap();
	assert_eq!(report["schema"], "exacopy.cli.verify");
	assert_eq!(report["schema_version"], "1.0");
	report
}

fn inconclusive(output: Output, code: i32, error: &str) -> Value {
	let report = verify_report(output, code);
	assert_eq!(report["result"], "inconclusive");
	assert_eq!(report["complete"], false);
	assert_eq!(report["error"]["code"], error);
	report
}

fn identity(path: &Path) -> (u64, u64) {
	let metadata = fs::metadata(path).unwrap();
	(metadata.dev(), metadata.ino())
}

fn assert_preserved(path: &Path, original_identity: (u64, u64), bytes: &[u8]) {
	assert_eq!(identity(path), original_identity);
	assert_eq!(fs::read(path).unwrap(), bytes);
}

struct Fixture(PathBuf);

impl Fixture {
	fn new() -> Self {
		static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
		const MAX_ATTEMPTS: usize = 128;
		for _ in 0..MAX_ATTEMPTS {
			let path = std::env::temp_dir().join(format!(
				"exacopy-cli-manifest-{}-{}",
				std::process::id(),
				SEQUENCE.fetch_add(1, Ordering::Relaxed)
			));
			match DirBuilder::new().mode(0o700).create(&path) {
				Ok(()) => return Self(path),
				Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
				Err(error) => panic!("could not create manifest fixture directory: {error}"),
			}
		}
		panic!("could not allocate manifest fixture directory");
	}

	fn command(&self) -> Command {
		let mut command = Command::new(env!("CARGO_BIN_EXE_exacopy"));
		command.current_dir(&self.0);
		command
	}

	fn create_baseline(&self, name: &OsStr) -> Vec<u8> {
		let output = self
			.command()
			.args(["manifest", "create", "--"])
			.arg(name)
			.output()
			.unwrap();
		assert_exit(&output, 0);
		assert!(output.stderr.is_empty(), "{output:?}");
		fs::write(self.0.join(BASELINE), &output.stdout).unwrap();
		output.stdout
	}

	fn verify(&self, name: &OsStr, format: &str) -> Output {
		self.command()
			.args(["verify", "--"])
			.arg(name)
			.args(["--manifest", BASELINE, "--format", format])
			.output()
			.unwrap()
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}
