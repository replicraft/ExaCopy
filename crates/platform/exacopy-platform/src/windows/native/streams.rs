use std::io;
use std::mem::{align_of, offset_of, size_of};
use std::os::windows::io::{AsRawHandle, BorrowedHandle};

use windows_sys::Win32::Storage::FileSystem::{
	FILE_STREAM_INFO, FileStreamInfo, GetFileInformationByHandleEx,
};

const STREAM_NAME_CAPACITY: usize = 256;
const DATA_STREAM: [u16; 7] = [58, 58, 36, 68, 65, 84, 65]; // ::$DATA

#[derive(Debug)]
pub(in crate::windows) enum StreamError {
	Query(io::Error),
	Unsupported,
}

#[repr(C, align(8))]
struct StreamBuffer {
	next: u32,
	name_bytes: u32,
	size: i64,
	allocation: i64,
	name: [u16; STREAM_NAME_CAPACITY],
}

const _: () = {
	assert!(align_of::<StreamBuffer>() == 8);
	assert!(offset_of!(StreamBuffer, next) == offset_of!(FILE_STREAM_INFO, NextEntryOffset));
	assert!(offset_of!(StreamBuffer, name_bytes) == offset_of!(FILE_STREAM_INFO, StreamNameLength));
	assert!(offset_of!(StreamBuffer, size) == offset_of!(FILE_STREAM_INFO, StreamSize));
	assert!(
		offset_of!(StreamBuffer, allocation) == offset_of!(FILE_STREAM_INFO, StreamAllocationSize)
	);
	assert!(offset_of!(StreamBuffer, name) == offset_of!(FILE_STREAM_INFO, StreamName));
};

/// Samples the inventory of a held, independently admitted local NTFS regular file.
/// The caller controls object custody and performs any required later rechecks.
pub(in crate::windows) fn require_unnamed_stream(
	handle: BorrowedHandle<'_>,
	extent: u64,
) -> Result<(), StreamError> {
	let mut stream = StreamBuffer {
		next: 0,
		name_bytes: 0,
		size: 0,
		allocation: 0,
		name: [0; STREAM_NAME_CAPACITY],
	};
	let size = u32::try_from(size_of::<StreamBuffer>()).map_err(|_| StreamError::Unsupported)?;
	// SAFETY: The live handle and writable buffer are valid through this
	// synchronous query. The buffer is initialized, bounded, and the prefix
	// and alignment match FILE_STREAM_INFO.
	let success = unsafe {
		GetFileInformationByHandleEx(
			handle.as_raw_handle(),
			FileStreamInfo,
			(&raw mut stream).cast(),
			size,
		)
	};
	if success == 0 {
		return Err(StreamError::Query(io::Error::last_os_error()));
	}
	if matches_unnamed_extent(&stream, extent) {
		Ok(())
	} else {
		Err(StreamError::Unsupported)
	}
}

fn matches_unnamed_extent(stream: &StreamBuffer, extent: u64) -> bool {
	stream.next == 0
		&& usize::try_from(stream.name_bytes).ok() == Some(size_of_val(&DATA_STREAM))
		&& stream.name.starts_with(&DATA_STREAM)
		&& u64::try_from(stream.size).ok() == Some(extent)
		&& stream.allocation >= 0
}

#[cfg(test)]
mod tests {
	use super::{StreamBuffer, matches_unnamed_extent};

	fn stream(size: i64) -> StreamBuffer {
		let mut name = [0; 256];
		for (unit, expected) in name.iter_mut().zip("::$DATA".encode_utf16()) {
			*unit = expected;
		}
		StreamBuffer {
			next: 0,
			name_bytes: 14,
			size,
			allocation: 4096,
			name,
		}
	}

	#[test]
	fn accepts_exact_counted_terminal_unnamed_stream() {
		assert!(matches_unnamed_extent(&stream(0), 0));
		let mut value = stream(17);
		value.name[7] = 0x0041;
		assert!(matches_unnamed_extent(&value, 17));
	}

	#[test]
	fn refuses_additional_unnamed_alias_or_unconfirmed_extent() {
		let alterations: [fn(&mut StreamBuffer); 7] = [
			|value| value.next = 40,
			|value| value.name_bytes = 0,
			|value| value.name_bytes = 13,
			|value| value.name_bytes = 16,
			|value| value.name[1] = 0x0041,
			|value| value.size = -1,
			|value| value.allocation = -1,
		];
		for mutate in alterations {
			let mut value = stream(17);
			mutate(&mut value);
			assert!(!matches_unnamed_extent(&value, 17));
		}
		assert!(!matches_unnamed_extent(&stream(16), 17));
	}
}
