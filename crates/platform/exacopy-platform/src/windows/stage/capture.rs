//! Capture and inspection capabilities for an already authorized private NTFS directory.

use std::fs::File;
use std::io;
use std::os::windows::io::AsHandle;

use exacopy_endpoint::{ClosedStage, FreshStage, MAX_FILE_LENGTH, ReadView};
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

use super::{
	Location, MAX_WINDOWS_STAGE_IO_BYTES, ObjectId, ObservedStage, READ_ACCESS, WindowsComponent,
	WindowsStageDirectory, WindowsStageError, WindowsStageReadBack, WindowsStageWriter,
};

#[cfg(test)]
mod tests;

/// A data barrier observed on the live stage's exact written prefix.
///
/// This is a file fact. Appending and confirming a durable checkpoint belongs
/// to the job journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsStagePrefix {
	parent: ObjectId,
	stage: ObjectId,
	end: u64,
}

impl WindowsStagePrefix {
	/// Identity of the original held private directory.
	#[must_use]
	pub const fn parent(&self) -> ObjectId {
		self.parent
	}

	/// Identity of the original exclusively created stage.
	#[must_use]
	pub const fn stage(&self) -> ObjectId {
		self.stage
	}

	/// Exclusive byte end of the prefix synchronized through the writer.
	#[must_use]
	pub const fn end(&self) -> u64 {
		self.end
	}
}

impl WindowsStageWriter<'_> {
	/// Synchronizes the original held stage at exactly the current nonempty prefix.
	///
	/// # Errors
	/// Refuses an invalid request or retired writer. Failed identity, stamp or
	/// barrier observations retire the writer and retain the stage for inspection.
	pub fn sync_written_prefix(
		&mut self,
		end: u64,
	) -> Result<WindowsStagePrefix, WindowsStageError> {
		self.sync_prefix_with(end, File::sync_all)
	}

	pub(super) fn sync_prefix_with(
		&mut self,
		end: u64,
		sync: impl FnOnce(&File) -> io::Result<()>,
	) -> Result<WindowsStagePrefix, WindowsStageError> {
		if self.file.is_none() {
			return Err(WindowsStageError::WriterRetired);
		}
		if end == 0 || end != self.written {
			return Err(WindowsStageError::InvalidRange);
		}
		let file = self.file.take().ok_or(WindowsStageError::WriterRetired)?;
		let before = self.location.check(file.as_handle(), end)?;
		sync(&file).map_err(WindowsStageError::Barrier)?;
		if self.location.check(file.as_handle(), end)? != before {
			return Err(WindowsStageError::Changed);
		}
		self.file = Some(file);
		Ok(WindowsStagePrefix {
			parent: self.location.parent.identity,
			stage: self.location.identity,
			end,
		})
	}
}

impl<'stage> FreshStage for WindowsStageWriter<'stage> {
	type Error = WindowsStageError;
	type Closed = WindowsStageReadBack<'stage>;

	const MAX_CHUNK_BYTES: usize = MAX_WINDOWS_STAGE_IO_BYTES;

	fn unwritten_length(&self) -> Result<u64, Self::Error> {
		let file = self.file.as_ref().ok_or(WindowsStageError::WriterRetired)?;
		if self.written != 0 {
			return Err(WindowsStageError::InvalidRange);
		}
		self.location.check(file.as_handle(), 0)?;
		Ok(self.length)
	}

	fn write_next(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
		self.write_at(self.written, buffer)
	}

	fn sync_and_close(self) -> Result<Self::Closed, Self::Error> {
		self.finish()
	}
}

impl<'stage> ClosedStage for WindowsStageReadBack<'stage> {
	type Error = WindowsStageError;
	type Reader<'view>
		= WindowsStageView<'view, 'stage>
	where
		Self: 'view;

	fn open_read_back(&self) -> Result<Self::Reader<'_>, Self::Error> {
		self.observation.check_eof()?;
		Ok(WindowsStageView {
			stage: &self.observation,
		})
	}
}

/// Read-only view borrowed from a stage with a confirmed writer close.
///
/// Operations use separate read-only handles, preserving the original
/// post-close pin and its cursor.
pub struct WindowsStageView<'view, 'stage> {
	stage: &'view ObservedStage<'stage>,
}

impl ReadView for WindowsStageView<'_, '_> {
	type Error = WindowsStageError;

	fn length(&self) -> u64 {
		self.stage.length
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.stage.check_eof()
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		self.stage.read_checked(offset, buffer)
	}
}

impl WindowsStageDirectory<'_> {
	/// Opens an existing private stage for inspection under this held directory.
	///
	/// The caller selects the exact expected file identity and extent from
	/// independently admitted history. An observation describes the selected
	/// stream now and does not establish historical flush, intent, or authority.
	///
	/// # Errors
	/// Refuses unsupported attributes, a reparse point, a different ID, spelling,
	/// or extent, an incompatible writer, and an unconfirmed observation.
	pub fn inspect_retained<'stage>(
		&'stage self,
		name: WindowsComponent<'stage>,
		expected: ObjectId,
		length: u64,
	) -> Result<WindowsRetainedStage<'stage>, WindowsStageError> {
		if length > MAX_FILE_LENGTH {
			return Err(WindowsStageError::InvalidExtent);
		}
		let location = Location {
			parent: self,
			name,
			identity: expected,
		};
		let file = location.open_read(FILE_SHARE_READ)?;
		let observed = location.check(file.as_handle(), length)?;
		let stage = ObservedStage {
			location,
			file,
			observed,
			length,
			reader_access: READ_ACCESS,
			reader_share: FILE_SHARE_READ,
		};
		stage.check_eof()?;
		Ok(WindowsRetainedStage { stage })
	}
}

/// An independently checked live view of a retained private stage.
///
/// Holding this read-only view gives no writer, publication, or cleanup rights.
///
/// ```compile_fail,E0277
/// use exacopy_endpoint::ClosedStage;
/// use exacopy_platform::windows::WindowsRetainedStage;
///
/// fn invalid_provenance(retained: &WindowsRetainedStage<'_>) {
///     let _ = ClosedStage::open_read_back(retained);
/// }
/// ```
pub struct WindowsRetainedStage<'stage> {
	stage: ObservedStage<'stage>,
}

impl WindowsRetainedStage<'_> {
	/// Returns the exact native file identity checked during admission.
	#[must_use]
	pub const fn identity(&self) -> ObjectId {
		self.stage.location.identity
	}
}

impl ReadView for WindowsRetainedStage<'_> {
	type Error = WindowsStageError;

	fn length(&self) -> u64 {
		self.stage.length
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.stage.check_eof()
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		self.stage.read_checked(offset, buffer)
	}
}
