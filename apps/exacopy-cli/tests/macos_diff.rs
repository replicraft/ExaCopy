//! Process-level byte comparison through the opt-in managed APFS adapter.
#![cfg(target_os = "macos")]

use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write as _};
use std::num::NonZeroUsize;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use exacopy_diff::{CompareError, LiveComparison, Side, compare, compare_parallel};
use exacopy_endpoint::{ReadView, UnixComponent};
use exacopy_platform::macos::{
	ManagedReadError, ManagedReadGrant, ManagedReadRoot, ManagedRegularFile, ManagedSourceName,
};
use serde_json::Value;

#[test]
fn compares_held_managed_apfs_files_and_preserves_inputs() {
	let fixture = Fixture::new();
	let left_root = fixture.managed_root("left-root");
	let right_root = fixture.managed_root("right-root");
	let original = vec![0; 96 * 1024];
	let mut changed = original.clone();
	let first = original.len() / 2 + 9;
	changed[first] = 0xA5;
	let name = "gauche-⚙";
	write_file(&left_root.join(name), &original);
	write_file(&left_root.join("equal"), &original);
	write_file(&left_root.join("changed"), &changed);
	write_file(&right_root.join("shorter"), &original[..first]);

	let equal = report(fixture.diff(&left_root, name, "equal").output(), 0);
	assert_eq!(equal["result"], "equal");
	assert_eq!(equal["complete"], true);
	assert_eq!(equal["length"], original.len().to_string());
	assert_eq!(equal["consistency"], "live_observed");

	for workers in [1, 4, 16] {
		let difference = report(
			fixture
				.diff(&left_root, name, "changed")
				.arg("--workers")
				.arg(workers.to_string())
				.output(),
			1,
		);
		assert_eq!(difference["result"], "different");
		assert_eq!(difference["complete"], true);
		assert_eq!(difference["consistency"], "live_observed");
		assert_eq!(difference["difference"]["kind"], "first_byte");
		assert_eq!(difference["difference"]["offset"], first.to_string());
	}

	let length = report(
		fixture
			.diff(&left_root, name, right_root.join("shorter"))
			.output(),
		1,
	);
	assert_eq!(length["result"], "different");
	assert_eq!(length["difference"]["kind"], "length");
	assert_eq!(length["difference"]["left"], original.len().to_string());
	assert_eq!(length["difference"]["right"], first.to_string());

	assert_eq!(
		fs::read(left_root.join(name)).expect("left bytes"),
		original
	);
	assert_eq!(
		fs::read(left_root.join("changed")).expect("right bytes"),
		changed,
	);
}

#[test]
fn refuses_symlinks_and_unprovisioned_parents_and_accepts_raw_names_for_admission() {
	let fixture = Fixture::new();
	let root = fixture.managed_root("managed");
	write_file(&root.join("present"), b"content");
	symlink("present", root.join("link")).expect("make terminal symlink");
	symlink(&root, fixture.0.join("root-link")).expect("make root alias");
	let unprovisioned = fixture.private_root("unprovisioned");
	write_file(&unprovisioned.join("file"), b"content");

	let raw = OsString::from_vec(b"absent-\xff".to_vec());
	for input in [
		root.join("link"),
		fixture.0.join("root-link/present"),
		unprovisioned.join("file"),
		root.join(raw),
	] {
		let refused = report(fixture.diff(&root, "present", &input).output(), 2);
		assert_eq!(refused["result"], "inconclusive", "{input:?}");
		assert_eq!(refused["complete"], false, "{input:?}");
		assert_eq!(refused["error"]["code"], "E_OPEN_INPUT", "{input:?}");
		assert!(refused.get("consistency").is_none(), "{input:?}");
	}
	assert_eq!(
		fs::read(root.join("present")).expect("surviving bytes"),
		b"content"
	);
}

#[test]
fn native_terminal_observation_refuses_a_same_length_replacement_after_reads() {
	let fixture = Fixture::new();
	let left_root = fixture.managed_root("left");
	let right_root = fixture.managed_root("right");
	const ORIGINAL: &[u8] = b"original";
	const REPLACEMENT: &[u8] = b"replaced";
	let left_path = left_root.join("file");
	write_file(&left_path, ORIGINAL);

	for workers in [None, NonZeroUsize::new(4)] {
		for check in [TerminalCheck::Require, TerminalCheck::DiscardRefusal] {
			let selected = right_root.join("file");
			let replacement = right_root.join("replacement");
			let retained = right_root.join("retained");
			write_file(&selected, ORIGINAL);
			write_file(&replacement, REPLACEMENT);
			let original_inode = fs::metadata(&selected).expect("stat original").ino();
			let replacement_inode = fs::metadata(&replacement).expect("stat replacement").ino();
			assert_ne!(original_inode, replacement_inode);

			let result = {
				let grant = ManagedReadGrant::trusted_owner_authorizes_provisioned_root;
				let left = ManagedReadRoot::open_provisioned_path(&left_root, grant())
					.expect("admit left managed root");
				let right = ManagedReadRoot::open_provisioned_path(&right_root, grant())
					.expect("admit right managed root");
				let component = UnixComponent::new(b"file").expect("valid fixture component");
				let name = ManagedSourceName::new(component).expect("prepare fixture name");
				let left = RebindView {
					file: left.open_regular(&name).expect("hold left file"),
					rebind: None,
					checks: AtomicUsize::new(0),
					bytes_read: AtomicUsize::new(0),
				};
				let selected_file = right.open_regular(&name).expect("hold right file");
				let identities = selected_file
					.observe_identities()
					.expect("observe right identity");
				assert_eq!(identities.file.inode().get(), original_inode);
				assert_eq!(
					identities.parent.inode().get(),
					fs::metadata(&right_root).expect("stat right root").ino()
				);
				let right = RebindView {
					file: selected_file,
					rebind: Some(Rebind {
						selected: &selected,
						replacement: &replacement,
						retained: &retained,
						check,
					}),
					checks: AtomicUsize::new(0),
					bytes_read: AtomicUsize::new(0),
				};
				let mut scratch = [0; 8];
				let result = match workers {
					Some(workers) => compare_parallel(&left, &right, &mut scratch, workers),
					None => compare(&left, &right, &mut scratch),
				};
				assert_eq!(left.bytes_read.load(Ordering::Relaxed), ORIGINAL.len());
				assert_eq!(right.bytes_read.load(Ordering::Relaxed), ORIGINAL.len());
				result
			};

			match check {
				TerminalCheck::Require => assert!(
					matches!(
						&result,
						Err(CompareError::Observation {
							side: Side::Right,
							source: ManagedReadError::SourceChanged,
						})
					),
					"replacement must make the comparison inconclusive: {result:?}"
				),
				TerminalCheck::DiscardRefusal => assert_eq!(
					result.expect("negative control ignores only the terminal refusal"),
					LiveComparison::Equal {
						length: ORIGINAL.len() as u64,
					}
				),
			}

			assert_eq!(
				fs::metadata(&retained).expect("stat retained").ino(),
				original_inode
			);
			assert_eq!(
				fs::metadata(&selected).expect("stat selected").ino(),
				replacement_inode
			);
			assert_eq!(fs::read(&left_path).expect("read untouched left"), ORIGINAL);
			assert_eq!(fs::read(&retained).expect("read retained right"), ORIGINAL);
			assert_eq!(fs::read(&selected).expect("read replacement"), REPLACEMENT);
			fs::remove_file(selected).expect("remove synthetic replacement");
			fs::remove_file(retained).expect("remove retained synthetic original");
		}
	}
}

#[derive(Clone, Copy)]
enum TerminalCheck {
	Require,
	DiscardRefusal,
}

struct Rebind<'a> {
	selected: &'a Path,
	replacement: &'a Path,
	retained: &'a Path,
	check: TerminalCheck,
}

struct RebindView<'a> {
	file: ManagedRegularFile<'a>,
	rebind: Option<Rebind<'a>>,
	checks: AtomicUsize,
	bytes_read: AtomicUsize,
}

impl ReadView for RebindView<'_> {
	type Error = ManagedReadError;

	fn length(&self) -> u64 {
		ReadView::length(&self.file)
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		let previous_checks = self.checks.fetch_add(1, Ordering::Relaxed);
		if let Some(rebind) = &self.rebind
			&& previous_checks == 1
		{
			assert_eq!(
				self.bytes_read.load(Ordering::Relaxed) as u64,
				self.length()
			);
			// A synthetic same-user writer deliberately bypasses the advisory lease.
			fs::rename(rebind.selected, rebind.retained).expect("retain original right file");
			fs::rename(rebind.replacement, rebind.selected).expect("replace selected right name");
			let result = ReadView::recheck_observation(&self.file);
			assert!(matches!(&result, Err(ManagedReadError::SourceChanged)));
			if matches!(rebind.check, TerminalCheck::DiscardRefusal) {
				return Ok(());
			}
			return result;
		}
		ReadView::recheck_observation(&self.file)
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		ReadView::read_exact_at(&self.file, offset, buffer)?;
		self.bytes_read.fetch_add(buffer.len(), Ordering::Relaxed);
		Ok(())
	}
}

fn write_file(path: &Path, bytes: &[u8]) {
	OpenOptions::new()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(path)
		.expect("create private test file")
		.write_all(bytes)
		.expect("write private test file");
}

fn report(output: std::io::Result<Output>, code: i32) -> Value {
	let output = output.expect("run exacopy diff");
	assert_eq!(
		output.status.code(),
		Some(code),
		"stdout = {}\nstderr = {}",
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr),
	);
	assert!(output.stderr.is_empty());
	let report: Value = serde_json::from_slice(&output.stdout).expect("read diff report");
	assert_eq!(report["schema"], "exacopy.cli.diff");
	assert_eq!(report["schema_version"], "1.0");
	assert_eq!(report["relation"], "bytes");
	report
}

struct Fixture(PathBuf);

impl Fixture {
	fn new() -> Self {
		static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
		const MAX_ATTEMPTS: usize = 128;
		let temp = Path::new("/private/tmp");
		for _ in 0..MAX_ATTEMPTS {
			let attempt = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
			let path = temp.join(format!(
				"exacopy-macos-diff-{}-{attempt}",
				std::process::id()
			));
			match DirBuilder::new().mode(0o700).create(&path) {
				Ok(()) => {
					let fixture = Self(path);
					fixture.compile_acl_helper();
					return fixture;
				}
				Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
				Err(error) => panic!("create private fixture directory: {error}"),
			}
		}
		panic!("exhausted synthetic fixture directory attempts");
	}

	fn compile_acl_helper(&self) {
		let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/macos/empty_acl.c");
		let compile = Command::new("/usr/bin/cc")
			.arg("-Wall")
			.arg("-Wextra")
			.arg("-Werror")
			.arg(source)
			.arg("-o")
			.arg(self.0.join("empty-acl"))
			.output()
			.expect("run macOS C compiler to build test ACL fixture");
		assert!(
			compile.status.success(),
			"compile ACL fixture: {}",
			String::from_utf8_lossy(&compile.stderr),
		);
	}

	fn private_root(&self, name: &str) -> PathBuf {
		let root = self.0.join(name);
		DirBuilder::new()
			.mode(0o700)
			.create(&root)
			.expect("create owner-private directory");
		root
	}

	fn managed_root(&self, name: &str) -> PathBuf {
		let root = self.private_root(name);
		let provision = Command::new(self.0.join("empty-acl"))
			.arg(&root)
			.output()
			.expect("run the ACL test helper");
		assert!(
			provision.status.success(),
			"provision test root: {}",
			String::from_utf8_lossy(&provision.stderr),
		);
		root
	}

	fn diff(&self, directory: &Path, left: impl AsRef<OsStr>, right: impl AsRef<OsStr>) -> Command {
		let mut command = Command::new(env!("CARGO_BIN_EXE_exacopy"));
		command
			.current_dir(directory)
			.arg("diff")
			.arg(left)
			.arg(right)
			.args(["--managed-macos", "--format", "json"]);
		command
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}
