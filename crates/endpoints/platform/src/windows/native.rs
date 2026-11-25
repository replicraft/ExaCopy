use std::io;
use std::mem::{align_of, offset_of, size_of};
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
	FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT,
	FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows_sys::Win32::Foundation::{
	INVALID_HANDLE_VALUE, NTSTATUS, STATUS_SUCCESS, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
	FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_OFFLINE,
	FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
	FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_ID_INFO, FILE_INFO_BY_HANDLE_CLASS,
	FILE_NAME_OPENED, FILE_STANDARD_INFO, FILE_TYPE_DISK, FILE_TYPE_UNKNOWN, FileAttributeTagInfo,
	FileIdInfo, FileStandardInfo, GetFileInformationByHandleEx, GetFileType,
	GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, VOLUME_NAME_GUID,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::{MAX_WINDOWS_COMPONENT_UNITS, WindowsComponent};

pub(super) const DATA_RECALL_ATTRIBUTES: u32 =
	FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;

#[derive(Debug)]
pub(crate) enum Refusal {
	QueryFailed(io::Error),
	NotDisk,
	ReparsePoint,
	WrongKind,
	DeletePending,
	NotNtfs,
	UnidentifiedVolume,
	UnidentifiedObject,
	ParentChanged,
	VolumeChanged,
	InvalidNameLength,
	OpenFailed(NTSTATUS),
	MissingOpenedHandle,
	UnexpectedOpenResult(usize),
}

impl std::fmt::Display for Refusal {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::QueryFailed(error) => write!(formatter, "handle query failed: {error}"),
			Self::OpenFailed(status) => write!(formatter, "relative open failed: {status:#010x}"),
			Self::UnexpectedOpenResult(info) => {
				write!(formatter, "unexpected relative open result: {info}")
			}
			refusal => write!(formatter, "{refusal:?}"),
		}
	}
}

/// Native physical identity combining the local volume GUID, serial and file ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectId {
	pub(super) volume: VolumeGuid,
	pub(super) volume_serial: u64,
	pub(super) file_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct VolumeGuid([u8; 36]);

// Keep C BOOLEAN values as bytes at the FFI boundary, even if a driver returns values
// outside the canonical Rust bool representation.
#[derive(Default)]
#[repr(C)]
pub(super) struct StandardInformation {
	pub(super) allocation_size: i64,
	pub(super) end_of_file: i64,
	pub(super) link_count: u32,
	pub(super) delete_pending: u8,
	pub(super) directory: u8,
}

const _: () = {
	assert!(size_of::<StandardInformation>() == size_of::<FILE_STANDARD_INFO>());
	assert!(align_of::<StandardInformation>() == align_of::<FILE_STANDARD_INFO>());
	assert!(
		offset_of!(StandardInformation, delete_pending)
			== offset_of!(FILE_STANDARD_INFO, DeletePending)
	);
	assert!(
		offset_of!(StandardInformation, directory) == offset_of!(FILE_STANDARD_INFO, Directory)
	);
};

#[derive(Clone, Copy)]
pub(super) enum Kind {
	Directory,
	RegularFile,
}

#[derive(Clone, Copy)]
pub(super) struct RelativeFileOpen {
	pub(super) access: u32,
	pub(super) share: u32,
	pub(super) disposition: u32,
	pub(super) attributes: u32,
	pub(super) expected_result: Option<usize>,
}

pub(super) fn open_relative_file(
	parent: BorrowedHandle<'_>,
	name: WindowsComponent<'_>,
	request: RelativeFileOpen,
) -> Result<OwnedHandle, Refusal> {
	open_relative_entry(parent, name, request, Kind::RegularFile)
}

pub(super) fn open_relative_entry(
	parent: BorrowedHandle<'_>,
	name: WindowsComponent<'_>,
	request: RelativeFileOpen,
	kind: Kind,
) -> Result<OwnedHandle, Refusal> {
	let kind = match kind {
		Kind::Directory => FILE_DIRECTORY_FILE,
		Kind::RegularFile => FILE_NON_DIRECTORY_FILE,
	};
	let units = name.as_units();
	let mut buffer = [0_u16; MAX_WINDOWS_COMPONENT_UNITS];
	buffer[..units.len()].copy_from_slice(units);
	let byte_len = u16::try_from(size_of_val(units)).map_err(|_| Refusal::InvalidNameLength)?;
	let mut native_name = UNICODE_STRING {
		Length: byte_len,
		MaximumLength: byte_len,
		Buffer: buffer.as_mut_ptr(),
	};
	let attrs = OBJECT_ATTRIBUTES {
		Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>())
			.map_err(|_| Refusal::InvalidNameLength)?,
		RootDirectory: parent.as_raw_handle(),
		ObjectName: &mut native_name,
		Attributes: request.attributes,
		SecurityDescriptor: null_mut(),
		SecurityQualityOfService: null_mut(),
	};
	let mut handle = null_mut();
	let mut status_block = IO_STATUS_BLOCK::default();
	// SAFETY: The borrowed parent stays live and all arguments point to initialized storage
	// that lives through the synchronous call. The counted, admitted name has one component.
	// The open uses a scoped disposition and opens the named entry itself on a reparse point.
	let status = unsafe {
		NtCreateFile(
			&mut handle,
			request.access,
			&attrs,
			&mut status_block,
			null(),
			0,
			request.share,
			request.disposition,
			kind | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
			null(),
			0,
		)
	};
	if status != STATUS_SUCCESS {
		return Err(Refusal::OpenFailed(status));
	}
	if handle.is_null() || handle == INVALID_HANDLE_VALUE {
		return Err(Refusal::MissingOpenedHandle);
	}
	// SAFETY: NtCreateFile succeeded and transferred an independently owned file handle.
	let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
	if request
		.expected_result
		.is_some_and(|expected| expected != status_block.Information)
	{
		return Err(Refusal::UnexpectedOpenResult(status_block.Information));
	}
	Ok(handle)
}

pub(super) fn observe(handle: BorrowedHandle<'_>, kind: Kind) -> Result<ObjectId, Refusal> {
	let info = observe_file(handle, kind)?;
	const MAX_EXTENDED_PATH_UNITS: usize = 32_768;
	let mut path = [0_u16; MAX_EXTENDED_PATH_UNITS];
	let count = local_ntfs_path(handle, FILE_NAME_OPENED, &mut path)?;
	let (volume, _) = parse_volume_guid(&path[..count])?;
	Ok(ObjectId {
		volume,
		volume_serial: info.VolumeSerialNumber,
		file_id: info.FileId.Identifier,
	})
}

pub(super) fn observe_file(
	handle: BorrowedHandle<'_>,
	kind: Kind,
) -> Result<FILE_ID_INFO, Refusal> {
	// SAFETY: The borrow keeps the file handle live through this synchronous query.
	let file_type = unsafe { GetFileType(handle.as_raw_handle()) };
	if file_type == FILE_TYPE_UNKNOWN {
		// GetFileType distinguishes an unknown type from a failed query through
		// the immediately observed last error. Do not discard that native cause.
		let error = io::Error::last_os_error();
		if error.raw_os_error() != Some(0) {
			return Err(Refusal::QueryFailed(error));
		}
	}
	if file_type != FILE_TYPE_DISK {
		return Err(Refusal::NotDisk);
	}
	let mut attrs = FILE_ATTRIBUTE_TAG_INFO::default();
	// SAFETY: The information class matches the initialized writable output type.
	unsafe { query(handle, FileAttributeTagInfo, &mut attrs)? };
	if attrs.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs.ReparseTag != 0 {
		return Err(Refusal::ReparsePoint);
	}
	let mut standard = StandardInformation::default();
	// SAFETY: StandardInformation matches the native storage and accepts any BOOLEAN bytes.
	unsafe { query(handle, FileStandardInfo, &mut standard)? };
	if standard.delete_pending != 0 {
		return Err(Refusal::DeletePending);
	}
	let directory = matches!(kind, Kind::Directory);
	if attrs.FileAttributes & (FILE_ATTRIBUTE_DEVICE | DATA_RECALL_ATTRIBUTES) != 0
		|| (attrs.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
		|| standard.directory != u8::from(directory)
	{
		return Err(Refusal::WrongKind);
	}
	let mut info = FILE_ID_INFO::default();
	// SAFETY: The information class matches the initialized writable output type.
	unsafe { query(handle, FileIdInfo, &mut info)? };
	if info.FileId.Identifier == [0; 16] {
		return Err(Refusal::UnidentifiedObject);
	}
	Ok(info)
}

/// Safety: `T` must be the native output type associated with `class`.
pub(super) unsafe fn query<T>(
	handle: BorrowedHandle<'_>,
	class: FILE_INFO_BY_HANDLE_CLASS,
	output: &mut T,
) -> Result<(), Refusal> {
	let len = u32::try_from(size_of::<T>()).map_err(|_| Refusal::UnidentifiedObject)?;
	// SAFETY: The caller associates the class with T. The exclusive reference and its known
	// size give the synchronous query aligned writable storage for the required native type.
	let success = unsafe {
		GetFileInformationByHandleEx(
			handle.as_raw_handle(),
			class,
			(&raw mut *output).cast(),
			len,
		)
	};
	if success == 0 {
		return Err(Refusal::QueryFailed(io::Error::last_os_error()));
	}
	Ok(())
}

/// Queries the filesystem and the GUID-qualified handle path, bounded by the caller's buffer.
pub(super) fn local_ntfs_path(
	handle: BorrowedHandle<'_>,
	spelling: u32,
	buffer: &mut [u16],
) -> Result<usize, Refusal> {
	const NTFS: [u16; 5] = [b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16, 0];
	let mut fs = [0_u16; 32];
	// SAFETY: The borrowed handle is live, the writable filesystem name buffer has the
	// declared capacity in UTF-16 units, and the other optional output buffers are null.
	let success = unsafe {
		GetVolumeInformationByHandleW(
			handle.as_raw_handle(),
			null_mut(),
			0,
			null_mut(),
			null_mut(),
			null_mut(),
			fs.as_mut_ptr(),
			32,
		)
	};
	if success == 0 {
		return Err(Refusal::QueryFailed(io::Error::last_os_error()));
	}
	if !fs.starts_with(&NTFS) {
		return Err(Refusal::NotNtfs);
	}
	let capacity = u32::try_from(buffer.len()).map_err(|_| Refusal::UnidentifiedVolume)?;
	// SAFETY: The borrowed handle and buffer are live and capacity matches its UTF-16 units.
	let count = unsafe {
		GetFinalPathNameByHandleW(
			handle.as_raw_handle(),
			buffer.as_mut_ptr(),
			capacity,
			VOLUME_NAME_GUID | spelling,
		)
	};
	if count == 0 {
		return Err(Refusal::QueryFailed(io::Error::last_os_error()));
	}
	if count >= capacity {
		return Err(Refusal::UnidentifiedVolume);
	}
	Ok(count as usize)
}

pub(super) fn parse_volume_guid(path: &[u16]) -> Result<(VolumeGuid, &[u16]), Refusal> {
	const PREFIX: &str = r"\\?\Volume{";
	const SUFFIX: [u16; 2] = [b'}' as u16, b'\\' as u16];
	let Some((prefix, tail)) = path.split_at_checked(PREFIX.len()) else {
		return Err(Refusal::UnidentifiedVolume);
	};
	let mut ascii = [0_u8; 36];
	let Some((guid, rest)) = tail.split_at_checked(ascii.len()) else {
		return Err(Refusal::UnidentifiedVolume);
	};
	if !prefix.iter().copied().eq(PREFIX.encode_utf16()) || !rest.starts_with(&SUFFIX) {
		return Err(Refusal::UnidentifiedVolume);
	}
	for (index, (out, &unit)) in ascii.iter_mut().zip(guid).enumerate() {
		let byte = u8::try_from(unit).map_err(|_| Refusal::UnidentifiedVolume)?;
		let valid = if matches!(index, 8 | 13 | 18 | 23) {
			byte == b'-'
		} else {
			byte.is_ascii_hexdigit()
		};
		if !valid {
			return Err(Refusal::UnidentifiedVolume);
		}
		*out = byte.to_ascii_lowercase();
	}
	Ok((VolumeGuid(ascii), &rest[SUFFIX.len()..]))
}
