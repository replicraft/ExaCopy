use std::fs::{self, DirBuilder, File};
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::atomic::{AtomicUsize, Ordering};

use exacopy_endpoint::UnixComponent;
use exacopy_model::{EntryId, JobId, RunEpoch};
use exacopy_platform::macos::staging::{
	ManagedStageGrant, ManagedStageRoot, StageBindingContext, StageDirectory, WriteStage,
};
use exacopy_platform::macos::{ManagedReadGrant, ManagedReadRoot, ManagedRegularFile};

const PRIVATE: &str = "private-stage";
const STAGE: &str = "candidate";
pub(super) const SOURCE: &str = "source";
pub(super) const TARGET: &str = "target";
pub(super) const PAYLOAD: &[u8] = b"\0a preserved\xff byte sequence";
pub(super) const ORIGINAL: &[u8] = b"incumbent content";

pub(super) struct Fixture {
	path: PathBuf,
	pub(super) destination: PathBuf,
	pub(super) independent: PathBuf,
	pub(super) stage: PathBuf,
}

impl Fixture {
	pub(super) fn new() -> Self {
		let path = allocate_directory();
		let destination = path.join("destination");
		let independent = path.join("independent");
		let private = destination.join(PRIVATE);
		let fixture = Self {
			path,
			destination,
			independent,
			stage: private.join(STAGE),
		};
		let helper = fixture.path.join("empty-acl");
		compile_acl_helper(&helper);
		for directory in [&fixture.destination, &fixture.independent, &private] {
			DirBuilder::new().mode(0o700).create(directory).unwrap();
			let output = Command::new(&helper).arg(directory).output().unwrap();
			assert!(
				output.status.success(),
				"provision synthetic APFS root: {}",
				String::from_utf8_lossy(&output.stderr),
			);
		}
		fixture
	}

	pub(super) fn stage_root(&self) -> ManagedStageRoot {
		ManagedStageRoot::from_provisioned_directory(
			File::open(&self.destination).unwrap(),
			ManagedStageGrant::trusted_owner_authorizes_provisioned_root(),
		)
		.expect("admit a provisioned APFS destination")
	}

	pub(super) fn read_root(&self) -> ManagedReadRoot {
		ManagedReadRoot::open_provisioned_path(&self.independent, read_grant())
			.expect("admit a separate APFS source root")
	}

	pub(super) fn stage_directory<'root>(
		&self,
		root: &'root ManagedStageRoot,
	) -> StageDirectory<'root> {
		root.open_stage_directory(component(PRIVATE))
			.expect("select provisioned private directory")
	}

	pub(super) fn same_parent_source<'root>(
		&self,
		root: &'root ManagedStageRoot,
	) -> ManagedRegularFile<'root> {
		root.open_regular_source(&self.destination, component(SOURCE), read_grant())
			.expect("select source under the destination lease")
	}

	pub(super) fn independent_source<'root>(
		&self,
		root: &'root ManagedReadRoot,
	) -> ManagedRegularFile<'root> {
		root.open_regular(component(SOURCE))
			.expect("select source under the independent lease")
	}

	pub(super) fn writer<'stage>(
		&self,
		directory: &'stage StageDirectory<'stage>,
		length: u64,
	) -> WriteStage<'stage> {
		let mut job = [0; 16];
		job[6] = 0x70;
		job[8] = 0x80;
		let context = StageBindingContext::new(
			JobId::try_from_bytes(job).expect("synthetic UUIDv7"),
			EntryId::new(1),
			RunEpoch::new(1),
		);
		directory
			.create_file(component(STAGE), component(TARGET), context, length)
			.expect("create private stage")
	}

	pub(super) fn assert_target_absent(&self) {
		assert_eq!(
			fs::symlink_metadata(self.destination.join(TARGET))
				.unwrap_err()
				.kind(),
			ErrorKind::NotFound
		);
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.path);
	}
}

pub(super) fn write_file(path: &Path, bytes: &[u8]) {
	File::options()
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(path)
		.unwrap()
		.write_all(bytes)
		.unwrap();
}

fn component(name: &str) -> UnixComponent<'_> {
	UnixComponent::new(name.as_bytes()).expect("synthetic component")
}

fn read_grant() -> ManagedReadGrant {
	ManagedReadGrant::trusted_owner_authorizes_provisioned_root()
}

fn allocate_directory() -> PathBuf {
	static NEXT: AtomicUsize = AtomicUsize::new(0);
	const MAX_ATTEMPTS: usize = 64;
	for _ in 0..MAX_ATTEMPTS {
		let attempt = NEXT.fetch_add(1, Ordering::Relaxed);
		let path = Path::new("/private/tmp").join(format!(
			"exacopy-macos-transfer-{}-{attempt}",
			process::id()
		));
		match DirBuilder::new().mode(0o700).create(&path) {
			Ok(()) => return path,
			Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
			Err(error) => panic!("cannot allocate transfer APFS fixture: {error}"),
		}
	}
	panic!("exhausted synthetic APFS fixture directory attempts")
}

fn compile_acl_helper(helper: &Path) {
	let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fixtures/macos/empty_acl.c");
	let output = Command::new("/usr/bin/cc")
		.args(["-Wall", "-Wextra", "-Werror"])
		.arg(source)
		.arg("-o")
		.arg(helper)
		.output()
		.expect("compile synthetic APFS ACL fixture");
	assert!(
		output.status.success(),
		"compile APFS ACL fixture: {}",
		String::from_utf8_lossy(&output.stderr),
	);
}
