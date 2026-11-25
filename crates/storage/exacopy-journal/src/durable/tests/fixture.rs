use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use exacopy_endpoint::{JournalFileBarrier, JournalSegment};

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

pub(super) type TestSegment<'test> = FixtureSegment<'test, false>;
pub(super) type SimulatedDarwinSegment<'test> = FixtureSegment<'test, true>;

type Barrier<'test> = Box<dyn Fn(&File) -> io::Result<()> + 'test>;

/// Uses a held synthetic file. The callback can simulate a barrier or inject a failure.
pub(super) struct FixtureSegment<'test, const DARWIN: bool> {
	file: File,
	barrier: Barrier<'test>,
}

impl TestSegment<'_> {
	pub(super) fn held(file: File) -> Self {
		Self::with_barrier(file, File::sync_all)
	}
}

impl<'test, const DARWIN: bool> FixtureSegment<'test, DARWIN> {
	pub(super) fn with_barrier(
		file: File,
		barrier: impl Fn(&File) -> io::Result<()> + 'test,
	) -> Self {
		Self {
			file,
			barrier: Box::new(barrier),
		}
	}
}

impl<const DARWIN: bool> Read for FixtureSegment<'_, DARWIN> {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		self.file.read(buffer)
	}
}

impl<const DARWIN: bool> Seek for FixtureSegment<'_, DARWIN> {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		self.file.seek(position)
	}
}

impl<const DARWIN: bool> Write for FixtureSegment<'_, DARWIN> {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.file.write(bytes)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.file.flush()
	}
}

impl<const DARWIN: bool> JournalSegment for FixtureSegment<'_, DARWIN> {
	const BARRIER: JournalFileBarrier = if DARWIN {
		JournalFileBarrier::DarwinFullFsync
	} else {
		JournalFileBarrier::SyncAll
	};

	fn regular_length(&self) -> io::Result<Option<u64>> {
		let metadata = self.file.metadata()?;
		Ok(metadata.is_file().then_some(metadata.len()))
	}

	fn sync(&self) -> io::Result<()> {
		(self.barrier)(&self.file)
	}
}
