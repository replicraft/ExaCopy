//! In-memory test fixture for journal policy and frame provenance.

use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use exacopy_endpoint::{JournalFileBarrier, JournalSegment};

pub(super) struct SimulatedSegment<const DARWIN: bool> {
	cursor: Cursor<Vec<u8>>,
	regular: bool,
}

impl<const DARWIN: bool> SimulatedSegment<DARWIN> {
	pub(super) fn new(bytes: Vec<u8>, regular: bool) -> Self {
		Self {
			cursor: Cursor::new(bytes),
			regular,
		}
	}
}

impl<const DARWIN: bool> Read for SimulatedSegment<DARWIN> {
	fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
		self.cursor.read(bytes)
	}
}

impl<const DARWIN: bool> Write for SimulatedSegment<DARWIN> {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.cursor.write(bytes)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.cursor.flush()
	}
}

impl<const DARWIN: bool> Seek for SimulatedSegment<DARWIN> {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		self.cursor.seek(position)
	}
}

impl<const DARWIN: bool> JournalSegment for SimulatedSegment<DARWIN> {
	const BARRIER: JournalFileBarrier = if DARWIN {
		JournalFileBarrier::DarwinFullFsync
	} else {
		JournalFileBarrier::SyncAll
	};

	fn regular_length(&self) -> io::Result<Option<u64>> {
		if self.regular {
			Ok(Some(
				u64::try_from(self.cursor.get_ref().len()).map_err(io::Error::other)?,
			))
		} else {
			Ok(None)
		}
	}

	fn sync(&self) -> io::Result<()> {
		Ok(())
	}
}
