use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::MutexGuard;

use exacopy_endpoint::{JournalFileBarrier, JournalSegment};

use super::{handle::FileIdentity, job::FreshJournalNames};

#[cfg(test)]
#[path = "../../tests/unit/journal_segment.rs"]
mod tests;

/// A checked Linux journal file held for its exclusive writer.
/// The synchronization contract is Linux `File::sync_all` on the held object.
/// For a newly created segment, extent observations also check its original names.
pub struct LinuxJournalSegment<'lease> {
	file: File,
	lease: SegmentLease<'lease>,
}

enum SegmentLease<'lease> {
	Fresh {
		names: FreshJournalNames,
		identity: FileIdentity,
	},
	Recovered {
		_writer: MutexGuard<'lease, ()>,
	},
}

impl LinuxJournalSegment<'static> {
	pub(super) fn fresh(file: File, names: FreshJournalNames, identity: FileIdentity) -> Self {
		Self {
			file,
			lease: SegmentLease::Fresh { names, identity },
		}
	}
}

impl<'lease> LinuxJournalSegment<'lease> {
	pub(super) fn recovered(file: File, writer: MutexGuard<'lease, ()>) -> Self {
		Self {
			file,
			lease: SegmentLease::Recovered { _writer: writer },
		}
	}

	#[cfg(test)]
	pub(super) fn flags(&self) -> rustix::io::Result<rustix::fs::OFlags> {
		rustix::fs::fcntl_getfl(&self.file)
	}
}

impl fmt::Debug for LinuxJournalSegment<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("LinuxJournalSegment")
			.finish_non_exhaustive()
	}
}

impl Read for LinuxJournalSegment<'_> {
	fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
		self.file.read(buffer)
	}
}

impl Write for LinuxJournalSegment<'_> {
	fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
		self.file.write(buffer)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.file.flush()
	}
}

impl Seek for LinuxJournalSegment<'_> {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		self.file.seek(position)
	}
}

impl JournalSegment for LinuxJournalSegment<'_> {
	const BARRIER: JournalFileBarrier = JournalFileBarrier::SyncAll;

	fn regular_length(&self) -> io::Result<Option<u64>> {
		if let SegmentLease::Fresh { names, identity } = &self.lease {
			return names
				.recheck_segment(&self.file, *identity)
				.map(Some)
				.map_err(io::Error::other);
		}
		let metadata = self.file.metadata()?;
		Ok(metadata.is_file().then_some(metadata.len()))
	}

	fn sync(&self) -> io::Result<()> {
		self.file.sync_all()
	}
}
