use std::cell::Cell;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::fs::FileExt as _;

use exacopy_endpoint::{JournalFileBarrier, JournalSegment, write_all_at};

use super::{
	Error, WindowsBootstrapLayout, WindowsBootstrapRecords, WindowsBootstrapRoleObservations,
	WindowsBootstrapRootSelection, read_at,
};

/// Exclusive writer over an already provisioned, originally empty bootstrap segment.
///
/// Ownership rests on trusted provisioning, exact independently selected original
/// identities and the native exclusive data handle. The caller excludes retained or
/// newly acquired conflicting access to names, ACLs, ownership, attributes and all
/// data streams across the held ancestry and roles. The caller also establishes
/// required owner and namespace barriers. File sync provides no namespace barrier.
///
/// Failed custody or uncertain I/O retires this writer. Empty reads and writes
/// remain no-ops, and invalid write bounds may be refused before native work.
/// These outcomes do not reestablish usable custody.
pub struct WindowsBootstrapFreshSegment<'name> {
	pub(super) records: WindowsBootstrapRecords<'name>,
	cursor: usize,
	retired: Cell<bool>,
}

impl<'name> WindowsBootstrapFreshSegment<'name> {
	/// Opens the exact five provisioned roles and exclusively reopens the empty segment.
	///
	/// Supply the original physical identities known at exclusive provisioning,
	/// independent of decoded history. The owner record must be complete, with its
	/// writer closed. The segment name must still designate the original empty
	/// inode, with its provisioning writer closed. The layout's segment extent is
	/// the maximum writable length. No recovered nonempty segment is accepted.
	///
	/// # Errors
	/// Refuses a mismatched identity, occupied extent, unavailable exclusive access
	/// or unconfirmed native role observations.
	pub fn open_provisioned(
		root_path: &'name [u16],
		expected: WindowsBootstrapRoleObservations,
		layout: WindowsBootstrapLayout<'name>,
	) -> Result<Self, Error> {
		Self::open_for_scope(root_path, expected, layout, false)
	}

	pub(super) fn open_for_scope(
		root_path: &'name [u16],
		expected: WindowsBootstrapRoleObservations,
		layout: WindowsBootstrapLayout<'name>,
		capture_job: bool,
	) -> Result<Self, Error> {
		let root = WindowsBootstrapRootSelection {
			volume_guid: expected.root.volume_guid(),
			volume_serial: expected.root.volume_serial(),
			file_id: expected.root.file_id(),
		};
		let records = WindowsBootstrapRecords::open_with_access(
			root_path,
			root,
			layout,
			Some(expected),
			capture_job,
		)?;
		records.owner.eof()?;
		records.segment.eof()?;
		records.recheck()?;
		Ok(Self {
			records,
			cursor: 0,
			retired: Cell::new(false),
		})
	}

	pub(super) fn check(&self) -> io::Result<()> {
		if self.retired.get() {
			return Err(io::Error::other("Windows bootstrap segment retired"));
		}
		self.retain(self.records.recheck().map_err(io::Error::other))
	}

	fn length(&self) -> usize {
		self.records.segment.pin.stamp.length
	}

	fn retain<T>(&self, result: io::Result<T>) -> io::Result<T> {
		if result.is_err() {
			self.retired.set(true);
		}
		result
	}

	fn read_checked(&mut self, output: &mut [u8]) -> io::Result<usize> {
		self.check()?;
		let count = output.len().min(self.length() - self.cursor);
		let segment = &self.records.segment;
		if count == 0 {
			segment.eof().map_err(io::Error::other)?;
		} else {
			read_at(&segment.file, self.cursor as u64, &mut output[..count])
				.map_err(io::Error::other)?;
		}
		self.check()?;
		self.cursor += count;
		Ok(count)
	}

	fn write_checked(&mut self, input: &[u8], end: usize) -> io::Result<()> {
		self.check()?;
		self.records.segment.eof().map_err(io::Error::other)?;
		write_all_at(self.cursor as u64, input, |offset, bytes| {
			self.records.segment.file.seek_write(bytes, offset)
		})
		.map_err(io::Error::other)?;
		self.records
			.segment
			.confirm_write(self.records.layout.first_segment, end)
			.map_err(io::Error::other)?;
		self.records.segment.eof().map_err(io::Error::other)?;
		self.check()?;
		self.cursor = end;
		Ok(())
	}
}

impl fmt::Debug for WindowsBootstrapFreshSegment<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("WindowsBootstrapFreshSegment")
			.finish_non_exhaustive()
	}
}

impl Read for WindowsBootstrapFreshSegment<'_> {
	fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
		if output.is_empty() {
			return Ok(0);
		}
		let result = self.read_checked(output);
		self.retain(result)
	}
}

impl Seek for WindowsBootstrapFreshSegment<'_> {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		self.check()?;
		let offset = match position {
			SeekFrom::Start(offset) => usize::try_from(offset).ok(),
			SeekFrom::Current(offset) => shifted(self.cursor, offset),
			SeekFrom::End(offset) => shifted(self.length(), offset),
		};
		let cursor = offset
			.filter(|&offset| offset <= self.length())
			.ok_or(io::ErrorKind::InvalidInput)?;
		self.cursor = cursor;
		Ok(cursor as u64)
	}
}

impl Write for WindowsBootstrapFreshSegment<'_> {
	fn write(&mut self, input: &[u8]) -> io::Result<usize> {
		if input.is_empty() {
			return Ok(0);
		}
		let end = self
			.cursor
			.checked_add(input.len())
			.filter(|&end| end <= self.records.layout.first_segment_bytes)
			.ok_or(io::ErrorKind::InvalidInput)?;
		if self.cursor != self.length() {
			return Err(io::ErrorKind::InvalidInput.into());
		}
		let result = self.write_checked(input, end);
		self.retain(result)?;
		Ok(input.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		self.check()
	}
}

impl JournalSegment for WindowsBootstrapFreshSegment<'_> {
	const BARRIER: JournalFileBarrier = JournalFileBarrier::SyncAll;

	fn regular_length(&self) -> io::Result<Option<u64>> {
		self.check()?;
		self.retain(self.records.segment.eof().map_err(io::Error::other))?;
		self.check()?;
		Ok(Some(self.length() as u64))
	}

	fn sync(&self) -> io::Result<()> {
		self.check()?;
		self.retain(self.records.segment.file.sync_all())?;
		self.retain(self.records.segment.eof().map_err(io::Error::other))?;
		self.check()
	}
}

fn shifted(origin: usize, delta: i64) -> Option<usize> {
	usize::try_from(i64::try_from(origin).ok()?.checked_add(delta)?).ok()
}
