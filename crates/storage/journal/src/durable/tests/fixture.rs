use std::fs::{self, File};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::frame::{ChainHead, FrameReader};

pub(super) struct ScratchFile(pub(super) PathBuf);

impl ScratchFile {
	pub(super) fn create() -> (Self, File) {
		static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);
		const MAX_ATTEMPTS: usize = 128;
		for _ in 0..MAX_ATTEMPTS {
			let attempt = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
			let path = std::env::temp_dir().join(format!(
				"exacopy-journal-test-{}-{attempt}",
				std::process::id()
			));
			match File::create_new(&path) {
				Ok(file) => return (Self(path), file),
				Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
				Err(error) => panic!("could not create a synthetic journal file: {error}"),
			}
		}
		panic!("could not acquire an exclusive synthetic journal file");
	}

	pub(super) fn bytes(&self) -> Vec<u8> {
		fs::read(&self.0).expect("read journal bytes independently")
	}

	pub(super) fn reopen(&self) -> File {
		File::options()
			.read(true)
			.write(true)
			.open(&self.0)
			.expect("reopen the journal fixture")
	}

	pub(super) fn reader(&self) -> FrameReader<File> {
		let read_handle = File::open(&self.0).expect("open journal for independent read");
		FrameReader::new(read_handle, ChainHead::start())
	}
}

impl Drop for ScratchFile {
	fn drop(&mut self) {
		let _ = fs::remove_file(&self.0);
	}
}
