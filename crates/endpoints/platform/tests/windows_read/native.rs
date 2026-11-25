use std::fs::File;
use std::io;
use std::mem::{align_of, offset_of, size_of};
use std::os::windows::fs::FileExt;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};

use exacopy_platform::windows::{MAX_WINDOWS_COMPONENT_UNITS, WindowsComponent};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
	FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
	NtCreateFile,
};
use windows_sys::Win32::Foundation::{
	INVALID_HANDLE_VALUE, NTSTATUS, STATUS_SUCCESS, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
	FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_OFFLINE,
	FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
	FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_ID_INFO, FILE_INFO_BY_HANDLE_CLASS,
	FILE_NAME_OPENED, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_READ, FILE_STANDARD_INFO,
	FILE_TYPE_DISK, FileAttributeTagInfo, FileIdInfo, FileStandardInfo,
	GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW,
	GetVolumeInformationByHandleW, SYNCHRONIZE, VOLUME_NAME_GUID,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

#[path = "native/by_id.rs"]
mod by_id;
#[path = "native/comparison.rs"]
mod comparison;
pub(super) use by_id::ByIdRefusal;

const DATA_RECALL_ATTRIBUTES: u32 =
	FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;

#[derive(Debug)]
pub(super) enum Refusal {
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
	InvalidReadRange,
	ReadFailed(io::Error),
}

impl std::fmt::Display for Refusal {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::QueryFailed(error) => write!(formatter, "handle query failed: {error}"),
			Self::OpenFailed(status) => write!(formatter, "relative open failed: {status:#010x}"),
			Self::ReadFailed(error) => write!(formatter, "positioned read failed: {error}"),
			refusal => write!(formatter, "{refusal:?}"),
		}
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ObjectId {
	volume: VolumeGuid,
	volume_serial: u64,
	file_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VolumeGuid([u8; 36]);

// Keep C BOOLEAN values as bytes at the FFI boundary, even if a driver returns values
// outside the canonical Rust bool representation.
#[derive(Default)]
#[repr(C)]
struct StandardInformation {
	allocation_size: i64,
	end_of_file: i64,
	link_count: u32,
	delete_pending: u8,
	directory: u8,
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
enum Kind {
	Directory,
	RegularFile,
}

/// A borrowed, already authorized parent. Its acquisition and path provenance are separate gates.
pub(super) struct HeldDirectory<'a> {
	handle: BorrowedHandle<'a>,
	identity: ObjectId,
}

impl<'a> HeldDirectory<'a> {
	pub(super) fn inspect(handle: BorrowedHandle<'a>) -> Result<Self, Refusal> {
		let identity = observe(handle, Kind::Directory)?;
		Ok(Self { handle, identity })
	}

	pub(super) fn open(&self, name: WindowsComponent<'_>) -> Result<RegularFile, Refusal> {
		// Re-observation catches reported drift. The native race gate must establish
		// how a change to a held parent's reparse state interacts with the relative open.
		self.check_parent()?;
		let handle = open_one(self.handle, name)?;
		let child = observe(handle.as_handle(), Kind::RegularFile)?;
		self.check_parent()?;
		if child.volume != self.identity.volume
			|| child.volume_serial != self.identity.volume_serial
		{
			return Err(Refusal::VolumeChanged);
		}
		Ok(RegularFile {
			file: handle.into(),
			identity: child,
		})
	}

	fn check_parent(&self) -> Result<(), Refusal> {
		if observe(self.handle, Kind::Directory)? != self.identity {
			return Err(Refusal::ParentChanged);
		}
		Ok(())
	}
}

/// An existing disk file opened with only read-data, read-attributes and synchronization rights.
pub(super) struct RegularFile {
	file: File,
	identity: ObjectId,
}

std::thread_local! {
	static POSITIONED_READ_CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

impl RegularFile {
	pub(super) fn identity(&self) -> ObjectId {
		self.identity
	}

	/// A short read or zero at EOF is returned to the caller. Rust's Windows read updates
	/// the private file cursor, so this method keeps exclusive access to the held handle.
	pub(super) fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<usize, Refusal> {
		let count = u32::try_from(buffer.len()).map_err(|_| Refusal::InvalidReadRange)?;
		let start = i64::try_from(offset).map_err(|_| Refusal::InvalidReadRange)?;
		start
			.checked_add(i64::from(count))
			.ok_or(Refusal::InvalidReadRange)?;
		if count == 0 {
			return Ok(0);
		}
		POSITIONED_READ_CALLS.set(POSITIONED_READ_CALLS.get() + 1);
		self.file
			.seek_read(buffer, offset)
			.map_err(Refusal::ReadFailed)
	}
}

fn open_one(
	parent: BorrowedHandle<'_>,
	name: WindowsComponent<'_>,
) -> Result<OwnedHandle, Refusal> {
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
		Attributes: 0,
		SecurityDescriptor: null_mut(),
		SecurityQualityOfService: null_mut(),
	};
	let mut handle = null_mut();
	let mut status_block = IO_STATUS_BLOCK::default();
	// SAFETY: The borrowed parent stays live and all arguments point to initialized storage
	// that lives through the synchronous call. The counted, admitted name has one component.
	// FILE_OPEN requests no creation, and FILE_OPEN_REPARSE_POINT opens the named entry itself.
	let status = unsafe {
		NtCreateFile(
			&mut handle,
			FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
			&attrs,
			&mut status_block,
			null(),
			0,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
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
	Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn observe(handle: BorrowedHandle<'_>, kind: Kind) -> Result<ObjectId, Refusal> {
	let info = observe_file(handle, kind)?;
	let volume = local_ntfs_volume(handle)?;
	Ok(ObjectId {
		volume,
		volume_serial: info.VolumeSerialNumber,
		file_id: info.FileId.Identifier,
	})
}

fn observe_file(handle: BorrowedHandle<'_>, kind: Kind) -> Result<FILE_ID_INFO, Refusal> {
	// SAFETY: The borrow keeps the file handle live through this synchronous query.
	if unsafe { GetFileType(handle.as_raw_handle()) } != FILE_TYPE_DISK {
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
unsafe fn query<T>(
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

fn local_ntfs_volume(handle: BorrowedHandle<'_>) -> Result<VolumeGuid, Refusal> {
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
	// The result can contain the original path. Retain only its volume GUID.
	const MAX_EXTENDED_PATH_UNITS: u32 = 32_768;
	let mut path = [0_u16; MAX_EXTENDED_PATH_UNITS as usize];
	// SAFETY: The borrowed handle and buffer are live and the buffer length matches its units.
	let count = unsafe {
		GetFinalPathNameByHandleW(
			handle.as_raw_handle(),
			path.as_mut_ptr(),
			MAX_EXTENDED_PATH_UNITS,
			VOLUME_NAME_GUID | FILE_NAME_OPENED,
		)
	};
	if count == 0 {
		return Err(Refusal::QueryFailed(io::Error::last_os_error()));
	}
	if count >= MAX_EXTENDED_PATH_UNITS {
		return Err(Refusal::UnidentifiedVolume);
	}
	parse_volume_guid(&path[..count as usize])
}

fn parse_volume_guid(path: &[u16]) -> Result<VolumeGuid, Refusal> {
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
	Ok(VolumeGuid(ascii))
}
