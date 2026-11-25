use std::io;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};

use exacopy_endpoint::{IoError, ReadView, read_exact_at};
use exacopy_platform::windows::WindowsComponent;
use windows_sys::Win32::Foundation::{ERROR_HANDLE_EOF, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING};
use windows_sys::Win32::Storage::FileSystem::{
	FILE_BASIC_INFO, FileBasicInfo, FileStandardInfo, ReadFile,
};
use windows_sys::Win32::System::IO::{
	GetOverlappedResult, OVERLAPPED, OVERLAPPED_0, OVERLAPPED_0_0,
};
use windows_sys::Win32::System::Threading::CreateEventW;

use super::{
	ByIdRefusal, HeldDirectory, Kind, ObjectId, Refusal, StandardInformation, observe_file, query,
};

#[derive(Debug)]
pub(in crate::native) enum CompareInputError {
	Open(ByIdRefusal),
	Query(Refusal),
	Read(io::Error),
	ExactRead(IoError),
	InconsistentObservation,
	InvalidRange,
}

impl std::fmt::Display for CompareInputError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Open(error) => write!(formatter, "{error}"),
			Self::Query(error) => write!(formatter, "{error}"),
			Self::Read(error) => write!(formatter, "{error}"),
			Self::ExactRead(error) => write!(formatter, "{error}"),
			Self::InconsistentObservation => formatter.write_str("file observation changed"),
			Self::InvalidRange => formatter.write_str("read exceeds the captured file extent"),
		}
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Observation {
	length: u64,
	write_time: i64,
	change_time: i64,
	attributes: u32,
}

pub(in crate::native) struct ComparisonFile {
	handle: OwnedHandle,
	identity: ObjectId,
	observation: Observation,
}

impl HeldDirectory<'_> {
	fn open_comparison(
		&mut self,
		name: WindowsComponent<'_>,
	) -> Result<ComparisonFile, CompareInputError> {
		let (handle, identity) = self
			.open_by_id_for_comparison(name)
			.map_err(CompareInputError::Open)?;
		let observation = observe_extent(handle.as_handle(), identity)?;
		Ok(ComparisonFile {
			handle,
			identity,
			observation,
		})
	}
}

impl ComparisonFile {
	fn confirm_extent(&self) -> Result<(), CompareInputError> {
		if observe_extent(self.handle.as_handle(), self.identity)? != self.observation {
			return Err(CompareInputError::InconsistentObservation);
		}
		Ok(())
	}
}

impl ReadView for ComparisonFile {
	type Error = CompareInputError;

	fn length(&self) -> u64 {
		self.observation.length
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		self.confirm_extent()?;
		let mut byte = [0];
		let count = read_at(self.handle.as_handle(), self.length(), &mut byte)
			.map_err(CompareInputError::Read)?;
		if count != 0 {
			return Err(CompareInputError::InconsistentObservation);
		}
		self.confirm_extent()
	}

	fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
		let length = u64::try_from(buffer.len()).map_err(|_| CompareInputError::InvalidRange)?;
		if !matches!(offset.checked_add(length), Some(end) if end <= self.length()) {
			return Err(CompareInputError::InvalidRange);
		}
		read_exact_at(offset, buffer, |position, remaining| {
			read_at(self.handle.as_handle(), position, remaining)
		})
		.map_err(CompareInputError::ExactRead)
	}
}

fn observe_extent(
	handle: BorrowedHandle<'_>,
	identity: ObjectId,
) -> Result<Observation, CompareInputError> {
	let id = observe_file(handle, Kind::RegularFile).map_err(CompareInputError::Query)?;
	if id.VolumeSerialNumber != identity.volume_serial || id.FileId.Identifier != identity.file_id {
		return Err(CompareInputError::InconsistentObservation);
	}
	let mut standard = StandardInformation::default();
	// SAFETY: The output is initialized and matches the native FileStandardInfo layout.
	unsafe { query(handle, FileStandardInfo, &mut standard) }.map_err(CompareInputError::Query)?;
	if standard.delete_pending != 0 || standard.directory != 0 {
		return Err(CompareInputError::InconsistentObservation);
	}
	let mut basic = FILE_BASIC_INFO::default();
	// SAFETY: The output is initialized and matches the native FileBasicInfo layout.
	unsafe { query(handle, FileBasicInfo, &mut basic) }.map_err(CompareInputError::Query)?;
	Ok(Observation {
		length: u64::try_from(standard.end_of_file)
			.map_err(|_| CompareInputError::InconsistentObservation)?,
		write_time: basic.LastWriteTime,
		change_time: basic.ChangeTime,
		attributes: basic.FileAttributes,
	})
}

fn read_at(handle: BorrowedHandle<'_>, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
	let amount = u32::try_from(buffer.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
	if amount == 0 {
		return Ok(0);
	}
	// SAFETY: An unnamed, initially unsignaled, manual-reset event needs no borrowed inputs.
	let raw_event = unsafe { CreateEventW(null(), 1, 0, null()) };
	if raw_event.is_null() {
		return Err(io::Error::last_os_error());
	}
	// SAFETY: CreateEventW returned a new owned handle.
	let event = unsafe { OwnedHandle::from_raw_handle(raw_event) };
	let offset_bytes = offset.to_le_bytes();
	let (low, high) = offset_bytes.split_at(4);
	let invalid_offset = |_| io::ErrorKind::InvalidInput;
	let overlapped_offset = OVERLAPPED_0_0 {
		Offset: u32::from_le_bytes(low.try_into().map_err(invalid_offset)?),
		OffsetHigh: u32::from_le_bytes(high.try_into().map_err(invalid_offset)?),
	};
	let mut request = OVERLAPPED {
		hEvent: event.as_raw_handle(),
		Anonymous: OVERLAPPED_0 {
			Anonymous: overlapped_offset,
		},
		..OVERLAPPED::default()
	};
	// SAFETY: The private file handle was opened with FILE_FLAG_OVERLAPPED. The buffer and
	// request have exclusive, live storage. The event is unique to this request, and the
	// completion wait below keeps all three live until the kernel finishes.
	let started = unsafe {
		ReadFile(
			handle.as_raw_handle(),
			buffer.as_mut_ptr(),
			amount,
			null_mut(),
			&raw mut request,
		)
	};
	if started == 0 {
		let error = io::Error::last_os_error();
		if error.raw_os_error() != Some(ERROR_IO_PENDING.cast_signed()) {
			return read_error(error);
		}
	}
	let mut transferred = 0;
	loop {
		// SAFETY: The same handle and request are used. The unique event supports a blocking
		// wait without consuming another request's signal. The buffer remains untouched.
		let complete = unsafe {
			GetOverlappedResult(
				handle.as_raw_handle(),
				&raw const request,
				&mut transferred,
				1,
			)
		};
		if complete != 0 {
			return usize::try_from(transferred).map_err(|_| io::ErrorKind::InvalidData.into());
		}
		let error = io::Error::last_os_error();
		if !matches!(
			error.raw_os_error().map(i32::cast_unsigned),
			Some(ERROR_IO_INCOMPLETE | ERROR_IO_PENDING)
		) {
			return read_error(error);
		}
	}
}

fn read_error(error: io::Error) -> io::Result<usize> {
	if error.raw_os_error() == Some(ERROR_HANDLE_EOF.cast_signed()) {
		return Ok(0);
	}
	Err(error)
}

#[cfg(test)]
#[path = "comparison_tests.rs"]
mod tests;
