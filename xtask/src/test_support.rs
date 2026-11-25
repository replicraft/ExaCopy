use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct Fixture(PathBuf);

impl Fixture {
	pub(crate) fn new() -> Self {
		let root = std::env::temp_dir().join(format!(
			"exacopy-xtask-{}-{}",
			std::process::id(),
			NEXT_ID.fetch_add(1, Ordering::Relaxed)
		));
		fs::create_dir(&root).expect("create the isolated policy fixture");
		Self(root)
	}

	pub(crate) fn root(&self) -> &Path {
		&self.0
	}

	pub(crate) fn write(&self, path: &str, contents: &str) -> PathBuf {
		let path = self.0.join(path);
		fs::create_dir_all(path.parent().expect("fixture path has a parent"))
			.expect("create fixture's parent directory");
		fs::write(&path, contents).expect("write policy fixture");
		path
	}
}

impl Drop for Fixture {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}
