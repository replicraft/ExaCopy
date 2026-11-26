use std::fs;
use std::io;
use std::os::windows::fs::{symlink_dir, symlink_file};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::Value;

use super::exacopy;

#[test]
#[ignore = "requires an explicitly provisioned fixed local NTFS root"]
fn ordinary_ntfs_compares_and_preserves_regular_files() {
	let fixture = Fixture::new();
	let left = fixture.0.join("left");
	let right = fixture.0.join("right");
	let different = fixture.0.join("different");
	let short = fixture.0.join("short");
	fs::write(&left, b"abc").unwrap();
	fs::write(&right, b"abc").unwrap();
	fs::write(&different, b"axc").unwrap();
	fs::write(&short, b"ab").unwrap();

	for (other, code, result) in [
		(&right, 0, "equal"),
		(&different, 1, "different"),
		(&short, 1, "different"),
	] {
		for workers in [&[][..], &["--workers", "3"][..]] {
			let output = compare(&left, other, workers);
			assert_eq!(
				output.status.code(),
				Some(code),
				"{}",
				String::from_utf8_lossy(&output.stdout)
			);
			let report: Value = serde_json::from_slice(&output.stdout).unwrap();
			assert_eq!(report["result"], result);
			assert_eq!(report["complete"], true);
			assert_eq!(report["consistency"], "live_observed");
			match report["difference"]["kind"].as_str() {
				Some("first_byte") => assert_eq!(report["difference"]["offset"], "1"),
				Some("length") => {
					assert_eq!(report["difference"]["left"], "3");
					assert_eq!(report["difference"]["right"], "2");
				}
				None if code == 0 => assert_eq!(report["length"], "3"),
				witness => panic!("unexpected difference witness {witness:?}"),
			}
		}
	}
	for (path, bytes) in [
		(left, b"abc".as_slice()),
		(right, b"abc"),
		(different, b"axc"),
		(short, b"ab"),
	] {
		assert_eq!(fs::read(path).unwrap(), bytes);
	}
}

#[test]
#[ignore = "requires explicit permission to create symlinks in the NTFS fixture"]
fn refuses_native_reparse_leaf_and_parent() {
	let fixture = Fixture::new();
	let actual = fixture.0.join("actual");
	fs::create_dir(&actual).unwrap();
	let regular = actual.join("source");
	fs::write(&regular, b"source").unwrap();

	let file_link = fixture.0.join("leaf-link");
	let directory_link = fixture.0.join("directory-link");
	symlink_file(&regular, &file_link).unwrap();
	symlink_dir(&actual, &directory_link).unwrap();
	for input in [&file_link, &directory_link.join("source")] {
		assert_eq!(fs::read(input).unwrap(), b"source", "following control");
		let output = compare(&regular, input, &[]);
		assert_eq!(output.status.code(), Some(2));
		let report: Value = serde_json::from_slice(&output.stdout).unwrap();
		assert_eq!(report["error"]["code"], "E_OPEN_INPUT");
		assert_eq!(report["complete"], false);
	}
	assert_eq!(fs::read(regular).unwrap(), b"source");
}

#[test]
#[ignore = "requires an explicitly provisioned fixed local NTFS root"]
fn ordinary_ntfs_compares_hard_link_aliases_read_only() {
	let fixture = Fixture::new();
	let source = fixture.0.join("source");
	let alias = fixture.0.join("alias");
	let payload = b"source\0\xFF";
	fs::write(&source, payload).expect("create the synthetic file");
	fs::hard_link(&source, &alias).expect("create a real NTFS hard-link alias");
	let before = fs::metadata(&source).expect("observe synthetic source");
	let outcome = compare(&source, &alias, &["--workers", "3"]);
	assert_eq!(outcome.status.code(), Some(0));
	let report: Value = serde_json::from_slice(&outcome.stdout).expect("read alias report");
	assert_eq!(report["result"], "equal");
	assert_eq!(report["complete"], true);
	assert_eq!(report["consistency"], "live_observed");
	assert_eq!(report["length"], payload.len().to_string());
	for path in [source, alias] {
		assert_eq!(fs::read(&path).expect("read a synthetic alias"), payload);
		let after = fs::metadata(path).expect("observe alias after comparison");
		assert_eq!(after.modified().unwrap(), before.modified().unwrap());
		assert_eq!(after.created().unwrap(), before.created().unwrap());
	}
}

#[test]
#[ignore = "requires an explicitly provisioned fixed local NTFS root"]
fn ordinary_ntfs_refuses_raw_stream_dot_and_verbatim_operands() {
	let fixture = Fixture::new();
	let source = fixture.0.join("source");
	fs::write(&source, b"source").expect("create the synthetic source");
	let source_text = source.to_str().expect("hosted fixture path is Unicode");
	let parent = fixture.0.to_str().expect("hosted fixture path is Unicode");
	for ambiguous in [
		format!("{source_text}:stream"),
		format!(r"{parent}\.\source"),
		format!(r"\\?\{source_text}"),
	] {
		let outcome = compare(&source, Path::new(&ambiguous), &[]);
		assert_eq!(outcome.status.code(), Some(2), "{ambiguous}");
		let report: Value = serde_json::from_slice(&outcome.stdout).expect("read path refusal");
		assert_eq!(report["result"], "inconclusive");
		assert_eq!(report["complete"], false);
		assert_eq!(report["error"]["code"], "E_INVALID_PATH");
		assert!(report.get("consistency").is_none());
	}
	assert_eq!(
		fs::read(source).expect("read preserved synthetic source"),
		b"source"
	);
}

fn compare(left: &Path, right: &Path, options: &[&str]) -> Output {
	exacopy()
		.arg("diff")
		.arg(left)
		.arg(right)
		.args(["--local-ntfs", "--format", "json"])
		.args(options)
		.output()
		.expect("invoke the NTFS comparison")
}

struct Fixture(PathBuf);

impl Fixture {
	fn new() -> Self {
		static NEXT: AtomicU32 = AtomicU32::new(0);
		let root = std::env::var_os("EXACOPY_WINDOWS_NTFS_ROOT")
			.expect("supply a disposable fixed local NTFS fixture root");
		let root = PathBuf::from(root);
		for _ in 0..64 {
			let next = NEXT.fetch_add(1, Ordering::Relaxed);
			let directory = root.join(format!("exacopy-cli-{}-{next}", std::process::id()));
			match fs::create_dir(&directory) {
				Ok(()) => return Self(directory),
				Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
				Err(error) => panic!("could not create the comparison fixture ({error})"),
			}
		}
		panic!("comparison fixture directory selection exhausted");
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}
