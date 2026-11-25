use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Storage::FileSystem::{
	FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
	FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::{FSCTL_DELETE_REPARSE_POINT, FSCTL_SET_REPARSE_POINT};
use windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_MOUNT_POINT;

pub(super) fn junction_mutator(path: &Path) -> File {
	OpenOptions::new()
		.access_mode(FILE_WRITE_ATTRIBUTES | SYNCHRONIZE)
		.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
		.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
		.open(path)
		.expect("open the synthetic parent with attribute-only mutation rights")
}

pub(super) struct Junction<'a> {
	handle: BorrowedHandle<'a>,
	active: bool,
}

impl<'a> Junction<'a> {
	pub(super) fn set(handle: BorrowedHandle<'a>, target: &Path) -> Self {
		let input = mount_point_buffer(target);
		control(handle, FSCTL_SET_REPARSE_POINT, &input)
			.expect("set a junction tag on the empty synthetic directory");
		Self {
			handle,
			active: true,
		}
	}

	pub(super) fn clear(mut self) {
		remove_mount_point(self.handle).expect("clear the held fixture junction tag");
		self.active = false;
	}
}

impl Drop for Junction<'_> {
	fn drop(&mut self) {
		if self.active
			&& let Err(error) = remove_mount_point(self.handle)
		{
			eprintln!("fixture cleanup could not clear junction tag: {error}");
		}
	}
}

fn remove_mount_point(handle: BorrowedHandle<'_>) -> io::Result<()> {
	let mut input = [0_u8; 8];
	input[..4].copy_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
	control(handle, FSCTL_DELETE_REPARSE_POINT, &input)
}

fn mount_point_buffer(target: &Path) -> Vec<u8> {
	let full = fs::canonicalize(target).expect("canonicalize the fixture junction target");
	let wide: Vec<_> = full.as_os_str().encode_wide().collect();
	let prefix: Vec<_> = r"\\?\".encode_utf16().collect();
	let printable = wide
		.strip_prefix(prefix.as_slice())
		.expect("extended local path");
	assert_eq!(
		printable.get(1),
		Some(&u16::from(b':')),
		"local drive target: {full:?}"
	);
	let substitute: Vec<_> = r"\??\"
		.encode_utf16()
		.chain(printable.iter().copied())
		.collect();
	let substitute_len = u16::try_from(size_of_val(substitute.as_slice())).expect("bounded target");
	let print_len = u16::try_from(size_of_val(printable)).expect("bounded print name");
	let print_offset = substitute_len.checked_add(2).expect("bounded print offset");
	// MS-FSCC counts data after the 8-byte common header, including the four
	// 16-bit name fields and the two UTF-16 string terminators.
	let data_len = 10_u16
		.checked_add(print_offset)
		.and_then(|remaining| remaining.checked_add(print_len))
		.expect("bounded reparse data length");
	let mut input = Vec::from(IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
	for field in [data_len, 0, 0, substitute_len, print_offset, print_len] {
		input.extend(field.to_le_bytes());
	}
	for unit in substitute
		.into_iter()
		.chain([0])
		.chain(printable.iter().copied())
		.chain([0])
	{
		input.extend(unit.to_le_bytes());
	}
	assert_eq!(
		input.len() - 8,
		usize::from(data_len),
		"exact mount-point data length"
	);
	assert!(input.len() <= 16_384, "Windows reparse payload limit");
	input
}

fn control(handle: BorrowedHandle<'_>, code: u32, input: &[u8]) -> io::Result<()> {
	let length = u32::try_from(input.len()).expect("bounded reparse input");
	let mut returned = 0;
	// SAFETY: The live test handle is synchronous. The input slice and the byte-count
	// output live through the call. These set/delete operations have no output payload.
	let ok = unsafe {
		DeviceIoControl(
			handle.as_raw_handle(),
			code,
			input.as_ptr().cast(),
			length,
			null_mut(),
			0,
			&mut returned,
			null_mut(),
		)
	};
	if ok == 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(())
}
