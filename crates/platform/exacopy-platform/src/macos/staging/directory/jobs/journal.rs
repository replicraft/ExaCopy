//! Sole descriptor and managed namespace lease for a Darwin journal segment.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};

use exacopy_endpoint::{JournalFileBarrier, JournalSegment};
use rustix::fs;

use super::record::{FIRST_SEGMENT, check_record};
use super::{
	JobError, JournalDirectory, ManagedObjectIdentity, checked_component,
	with_materialization_disabled,
};

/// The exclusive journal byte cursor with its managed directory and held job.
pub struct DarwinJournalSegment<'job> {
	// The descriptor closes before the directory lease is released.
	file: File,
	identity: ManagedObjectIdentity,
	directory: JournalDirectory<'job>,
}

impl<'job> DarwinJournalSegment<'job> {
	pub(super) fn new(
		file: File,
		identity: ManagedObjectIdentity,
		directory: JournalDirectory<'job>,
	) -> Self {
		Self {
			file,
			identity,
			directory,
		}
	}

	fn check_current(&self, length: u64) -> Result<(), JobError> {
		self.directory.check_current()?;
		check_record(
			&self.directory.directory.lease,
			checked_component(FIRST_SEGMENT)?,
			&self.file,
			length,
			Some(self.identity),
		)?;
		Ok(())
	}
}

impl Read for DarwinJournalSegment<'_> {
	fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
		self.file.read(bytes)
	}
}

impl Write for DarwinJournalSegment<'_> {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.file.write(bytes)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.file.flush()
	}
}

impl Seek for DarwinJournalSegment<'_> {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		self.file.seek(position)
	}
}

impl JournalSegment for DarwinJournalSegment<'_> {
	const BARRIER: JournalFileBarrier = JournalFileBarrier::DarwinFullFsync;

	fn regular_length(&self) -> io::Result<Option<u64>> {
		let observed = self.file.metadata()?;
		Ok(observed.is_file().then_some(observed.len()))
	}

	fn sync(&self) -> io::Result<()> {
		with_materialization_disabled(|| {
			let held = fs::fstat(&self.file)?;
			let length = u64::try_from(held.st_size).map_err(|_| JobError::IdentityChanged)?;
			self.check_current(length)?;
			fs::fcntl_fullfsync(&self.file)?;
			self.check_current(length)
		})
		.map_err(io::Error::other)
	}
}

impl fmt::Debug for DarwinJournalSegment<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("DarwinJournalSegment")
			.finish_non_exhaustive()
	}
}
