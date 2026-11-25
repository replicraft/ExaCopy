use std::ffi::OsStr;
use std::fmt::Debug;
use std::fs::{self, DirBuilder, File};
use std::io::ErrorKind;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const MAX_DIRECTORY_ATTEMPTS: usize = 128;

pub(crate) struct Scratch(PathBuf);

impl Scratch {
	pub(crate) fn new() -> Self {
		for _ in 0..MAX_DIRECTORY_ATTEMPTS {
			let attempt = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
			let path = std::env::temp_dir().join(format!(
				"exacopy-linux-tests-{}-{attempt}",
				std::process::id()
			));

			match DirBuilder::new().mode(PRIVATE_DIRECTORY_MODE).create(&path) {
				Ok(()) => return Self(path),
				Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
				Err(error) => panic!("could not create synthetic directory {path:?}: {error}"),
			}
		}
		panic!("could not acquire a fresh directory for synthetic fixtures");
	}

	pub(crate) fn path(&self, name: impl AsRef<OsStr>) -> PathBuf {
		self.0.join(name.as_ref())
	}

	pub(crate) fn open(&self) -> File {
		File::open(&self.0).expect("open held fixture directory")
	}

	pub(crate) fn assert_debug_redacts(&self, capability: &impl Debug, names: &[&str]) {
		let text = format!("{capability:?}");
		let path_prefix = self
			.0
			.file_name()
			.and_then(OsStr::to_str)
			.expect("fixture directory has an ASCII name");
		assert!(
			!text.contains(path_prefix),
			"debug leaked a fixture path: {text}"
		);
		for name in names {
			assert!(!text.contains(name), "debug leaked a fixture name: {text}");
		}
	}
}

impl Drop for Scratch {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}
