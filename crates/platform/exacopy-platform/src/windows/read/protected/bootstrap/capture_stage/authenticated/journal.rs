use std::cell::Cell;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::fs::FileExt as _;

use exacopy_endpoint::{JournalFileBarrier, JournalSegment, write_all_at};

use super::super::super::read_at;
use super::super::{Binding, CaptureCustody, Directory, WindowsComponent};
use super::{
	MAX_WINDOWS_CAPTURE_SEGMENT_BYTES, Record, WindowsCaptureAdmission, WindowsCaptureEffect,
	WindowsStageIdentity,
};

#[derive(Clone, Copy)]
struct AppendWindow {
	start: usize,
	end: usize,
}

pub(super) struct AppendState {
	window: Cell<Option<AppendWindow>>,
	length: Cell<usize>,
	synced: Cell<usize>,
	retired: Cell<bool>,
}

impl AppendState {
	pub(super) const fn new() -> Self {
		Self {
			window: Cell::new(None),
			length: Cell::new(0),
			synced: Cell::new(0),
			retired: Cell::new(false),
		}
	}

	fn proposed(&self, offset: usize, length: usize) -> io::Result<AppendWindow> {
		self.ready()?;
		if self.window.get().is_some() || offset != self.synced.get() || offset != self.length.get()
		{
			return Err(io::ErrorKind::InvalidInput.into());
		}
		let end = offset
			.checked_add(length)
			.filter(|&end| end > offset && end <= MAX_WINDOWS_CAPTURE_SEGMENT_BYTES)
			.ok_or(io::ErrorKind::InvalidInput)?;
		Ok(AppendWindow { start: offset, end })
	}

	fn ready(&self) -> io::Result<()> {
		if self.retired.get() {
			return Err(io::Error::other("Windows capture journal retired"));
		}
		Ok(())
	}

	pub(super) fn finish(&self, extent: usize) -> io::Result<()> {
		self.ready()?;
		if self.window.get().is_some()
			|| extent == 0
			|| extent != self.length.get()
			|| extent != self.synced.get()
		{
			return Err(io::Error::other(
				"unconfirmed Windows capture journal extent",
			));
		}
		Ok(())
	}

	fn retain<T>(&self, result: io::Result<T>) -> io::Result<T> {
		if result.is_err() {
			self.retired.set(true);
		}
		result
	}
}

/// Scoped admission of one complete capture append on the original segment.
pub struct WindowsCaptureJournalAdmission<'stage, A> {
	admission: &'stage A,
	state: &'stage AppendState,
	identity: WindowsStageIdentity,
	custody: &'stage CaptureCustody<'stage, 'stage>,
	leaf: &'stage Binding,
}

impl<'stage, A: WindowsCaptureAdmission> WindowsCaptureJournalAdmission<'stage, A> {
	pub(super) fn new(
		admission: &'stage A,
		state: &'stage AppendState,
		identity: WindowsStageIdentity,
		custody: &'stage CaptureCustody<'stage, 'stage>,
		leaf: &'stage Binding,
	) -> Self {
		Self {
			admission,
			state,
			identity,
			custody,
			leaf,
		}
	}

	/// Admits one journal frame, including its exact envelope and file barrier.
	///
	/// Use immediately before the first subwrite and retain the returned guard
	/// until the complete file barrier has returned. No await belongs in that
	/// boundary. An unfinished window cannot authorize another append.
	/// # Errors
	/// Refuses changed custody, declined authority or an invalid append range.
	pub fn enter(
		&self,
		offset: u64,
		length: usize,
	) -> io::Result<WindowsCaptureJournalGuard<'_, A>> {
		let position = usize::try_from(offset).map_err(io::Error::other)?;
		let window = self.state.proposed(position, length)?;
		self.state
			.retain(self.custody.check_leaf(self.leaf).map_err(io::Error::other))?;
		let guard =
			self.state
				.retain(self.admission.enter(WindowsCaptureEffect::JournalAppend {
					segment: self.identity,
					offset,
					length,
				}))?;
		self.state.window.set(Some(window));
		Ok(WindowsCaptureJournalGuard {
			state: self.state,
			_guard: guard,
		})
	}
}

impl<A> fmt::Debug for WindowsCaptureJournalAdmission<'_, A> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("WindowsCaptureJournalAdmission")
			.finish_non_exhaustive()
	}
}

/// Current live admission of one exact frame write and barrier.
pub struct WindowsCaptureJournalGuard<'gate, A: WindowsCaptureAdmission + 'gate> {
	state: &'gate AppendState,
	_guard: A::Guard<'gate>,
}

impl<A: WindowsCaptureAdmission> fmt::Debug for WindowsCaptureJournalGuard<'_, A> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("WindowsCaptureJournalGuard")
			.finish_non_exhaustive()
	}
}

impl<A: WindowsCaptureAdmission> Drop for WindowsCaptureJournalGuard<'_, A> {
	fn drop(&mut self) {
		if let Some(window) = self.state.window.take()
			&& self.state.synced.get() != window.end
		{
			self.state.retired.set(true);
		}
	}
}

/// Original bounded append-only capture-file aperture within the paired scope.
pub struct WindowsCaptureJournalSegment<'stage> {
	record: &'stage mut Record,
	parent: &'stage Directory,
	name: WindowsComponent<'static>,
	state: &'stage AppendState,
	custody: &'stage CaptureCustody<'stage, 'stage>,
	leaf: &'stage Binding,
	cursor: usize,
}

impl<'stage> WindowsCaptureJournalSegment<'stage> {
	pub(super) fn new(
		record: &'stage mut Record,
		parent: &'stage Directory,
		name: WindowsComponent<'static>,
		state: &'stage AppendState,
		custody: &'stage CaptureCustody<'stage, 'stage>,
		leaf: &'stage Binding,
	) -> Self {
		Self {
			record,
			parent,
			name,
			state,
			custody,
			leaf,
			cursor: 0,
		}
	}

	fn check(&self) -> io::Result<()> {
		self.state.ready()?;
		self.state.retain((|| {
			self.custody
				.check_leaf(self.leaf)
				.map_err(io::Error::other)?;
			if self.record.pin.stamp.length != self.state.length.get() {
				return Err(io::ErrorKind::InvalidData.into());
			}
			self.record
				.check(self.parent, self.name)
				.map_err(io::Error::other)?;
			self.record.eof().map_err(io::Error::other)?;
			self.record
				.check(self.parent, self.name)
				.map_err(io::Error::other)?;
			self.custody.check_leaf(self.leaf).map_err(io::Error::other)
		})())
	}

	fn read_checked(&mut self, output: &mut [u8]) -> io::Result<usize> {
		self.check()?;
		let count = output.len().min(self.state.length.get() - self.cursor);
		if count != 0 {
			read_at(&self.record.file, self.cursor as u64, &mut output[..count])
				.map_err(io::Error::other)?;
		}
		self.check()?;
		self.cursor += count;
		Ok(count)
	}

	fn write_checked(&mut self, input: &[u8]) -> io::Result<()> {
		self.check()?;
		let window = self
			.state
			.window
			.get()
			.ok_or(io::ErrorKind::PermissionDenied)?;
		let end = self
			.cursor
			.checked_add(input.len())
			.filter(|&end| end <= window.end)
			.ok_or(io::ErrorKind::InvalidInput)?;
		if self.cursor < window.start || self.cursor != self.state.length.get() {
			return Err(io::ErrorKind::InvalidInput.into());
		}
		write_all_at(self.cursor as u64, input, |offset, bytes| {
			self.record.file.seek_write(bytes, offset)
		})
		.map_err(io::Error::other)?;
		self.record
			.confirm_write(self.name, end)
			.map_err(io::Error::other)?;
		self.state.length.set(end);
		self.check()?;
		self.cursor = end;
		Ok(())
	}

	fn sync_checked(&self) -> io::Result<()> {
		self.check()?;
		let window = self
			.state
			.window
			.get()
			.ok_or(io::ErrorKind::PermissionDenied)?;
		if self.state.synced.get() != window.start || self.state.length.get() != window.end {
			return Err(io::ErrorKind::InvalidInput.into());
		}
		self.record.file.sync_all()?;
		self.check()?;
		self.state.synced.set(window.end);
		Ok(())
	}
}

impl fmt::Debug for WindowsCaptureJournalSegment<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("WindowsCaptureJournalSegment")
			.finish_non_exhaustive()
	}
}

impl Read for WindowsCaptureJournalSegment<'_> {
	fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
		if output.is_empty() {
			return Ok(0);
		}
		let result = self.read_checked(output);
		self.state.retain(result)
	}
}

impl Seek for WindowsCaptureJournalSegment<'_> {
	fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
		self.check()?;
		let length = self.state.length.get();
		let offset = match position {
			SeekFrom::Start(offset) => usize::try_from(offset).ok(),
			SeekFrom::Current(delta) => self
				.cursor
				.checked_add_signed(isize::try_from(delta).map_err(io::Error::other)?),
			SeekFrom::End(delta) => {
				length.checked_add_signed(isize::try_from(delta).map_err(io::Error::other)?)
			}
		};
		self.cursor = offset
			.filter(|&offset| offset <= length)
			.ok_or(io::ErrorKind::InvalidInput)?;
		Ok(self.cursor as u64)
	}
}

impl Write for WindowsCaptureJournalSegment<'_> {
	fn write(&mut self, input: &[u8]) -> io::Result<usize> {
		if input.is_empty() {
			return Ok(0);
		}
		let result = self.write_checked(input);
		self.state.retain(result)?;
		Ok(input.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		self.check()
	}
}

impl JournalSegment for WindowsCaptureJournalSegment<'_> {
	const BARRIER: JournalFileBarrier = JournalFileBarrier::SyncAll;

	fn regular_length(&self) -> io::Result<Option<u64>> {
		self.check()?;
		Ok(Some(self.state.length.get() as u64))
	}

	fn sync(&self) -> io::Result<()> {
		self.state.retain(self.sync_checked())
	}
}

#[cfg(test)]
mod tests;
