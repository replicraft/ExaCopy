use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr::{self, null, null_mut};

use windows_sys::Win32::Foundation::{ERROR_NO_TOKEN, HANDLE, INVALID_HANDLE_VALUE, LUID};
use windows_sys::Win32::Security::{
	DACL_SECURITY_INFORMATION, GetKernelObjectSecurity, GetTokenInformation, LUID_AND_ATTRIBUTES,
	LookupPrivilegeValueW, OWNER_SECURITY_INFORMATION, SE_BACKUP_NAME, SE_MANAGE_VOLUME_NAME,
	SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME, SE_TAKE_OWNERSHIP_NAME, TOKEN_ELEVATION,
	TOKEN_INFORMATION_CLASS, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER,
	TokenElevation, TokenPrimary, TokenPrivileges, TokenStatistics, TokenUser,
};
use windows_sys::Win32::System::Threading::{
	GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

use super::{Error, acl};

mod privileges;

const MAX_SECURITY_BYTES: u32 = 16_384;
const TOKEN_USER_BYTES: u32 = 128;
const TOKEN_PRIVILEGES_BYTES: u32 =
	(privileges::HEADER_BYTES + 256 * privileges::ENTRY_BYTES) as u32;

const _: () = {
	assert!(offset_of!(TOKEN_PRIVILEGES, PrivilegeCount) == 0);
	assert!(offset_of!(TOKEN_PRIVILEGES, Privileges) == privileges::HEADER_BYTES);
	assert!(size_of::<LUID_AND_ATTRIBUTES>() == privileges::ENTRY_BYTES);
	assert!(offset_of!(LUID_AND_ATTRIBUTES, Luid) == 0);
	assert!(offset_of!(LUID_AND_ATTRIBUTES, Attributes) == 8);
	assert!(offset_of!(LUID, LowPart) == 0);
	assert!(offset_of!(LUID, HighPart) == 4);
};

#[repr(align(8))]
struct NativeBytes<const N: usize>([u8; N]);

#[derive(PartialEq, Eq)]
pub(super) struct Subject {
	pub(super) sid: Vec<u8>,
	token_id: (u32, i32),
	modified_id: (u32, i32),
}

impl Subject {
	pub(super) fn current() -> Result<Self, Error> {
		reject_impersonation()?;
		let mut handle = null_mut();
		// SAFETY: The pseudo-handle selects the calling process. The output is
		// valid writable storage for one handle and no privilege is enabled.
		let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) };
		if opened == 0 {
			return Err(Error::Unavailable);
		}
		let token = own_token(handle)?;
		let mut statistics = TOKEN_STATISTICS::default();
		let mut elevation = TOKEN_ELEVATION::default();
		// SAFETY: These information classes have the corresponding initialized
		// output types and sizes. The query handle stays borrowed.
		unsafe {
			query_fixed(token.as_handle(), TokenStatistics, &mut statistics)?;
			query_fixed(token.as_handle(), TokenElevation, &mut elevation)?;
		}
		if statistics.TokenType != TokenPrimary || elevation.TokenIsElevated != 0 {
			return Err(Error::Unsupported);
		}
		reject_storage_privileges(token.as_handle())?;
		let sid = token_user(token.as_handle())?;
		if sid == acl::SYSTEM || sid == acl::ADMINISTRATORS {
			return Err(Error::Unsupported);
		}
		reject_impersonation()?;
		let mut confirmed = TOKEN_STATISTICS::default();
		// SAFETY: TokenStatistics returns exactly TOKEN_STATISTICS.
		unsafe { query_fixed(token.as_handle(), TokenStatistics, &mut confirmed)? };
		let token_id = (statistics.TokenId.LowPart, statistics.TokenId.HighPart);
		let modified_id = (
			statistics.ModifiedId.LowPart,
			statistics.ModifiedId.HighPart,
		);
		if (confirmed.TokenId.LowPart, confirmed.TokenId.HighPart) != token_id
			|| (confirmed.ModifiedId.LowPart, confirmed.ModifiedId.HighPart) != modified_id
		{
			return Err(Error::Changed);
		}
		Ok(Self {
			sid,
			token_id,
			modified_id,
		})
	}
}

fn reject_impersonation() -> Result<(), Error> {
	let mut handle = null_mut();
	// SAFETY: The thread pseudo-handle selects this thread; the output is
	// writable for one token handle. OpenAsSelf changes the permission check,
	// not the selected token.
	let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut handle) };
	if opened != 0 {
		drop(own_token(handle)?);
		return Err(Error::Unsupported);
	}
	if io::Error::last_os_error().raw_os_error() == i32::try_from(ERROR_NO_TOKEN).ok() {
		Ok(())
	} else {
		Err(Error::Unsupported)
	}
}

fn own_token(handle: HANDLE) -> Result<OwnedHandle, Error> {
	if handle.is_null() || handle == INVALID_HANDLE_VALUE {
		return Err(Error::Unavailable);
	}
	// SAFETY: The successful token-open caller transferred a distinct live handle.
	Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

unsafe fn query_fixed<T>(
	handle: BorrowedHandle<'_>,
	class: TOKEN_INFORMATION_CLASS,
	value: &mut T,
) -> Result<(), Error> {
	let size = u32::try_from(size_of::<T>()).map_err(|_| Error::Unavailable)?;
	let mut written = 0;
	// SAFETY: The caller associates the class with the native output type T.
	// The initialized exclusive buffer and returned-count storage are live.
	let ok = unsafe {
		GetTokenInformation(
			handle.as_raw_handle(),
			class,
			(&raw mut *value).cast(),
			size,
			&mut written,
		)
	};
	if ok == 0 || written != size {
		return Err(Error::Unavailable);
	}
	Ok(())
}

fn reject_storage_privileges(handle: BorrowedHandle<'_>) -> Result<(), Error> {
	let mut disallowed = [(0, 0); 4];
	for (entry, name) in disallowed.iter_mut().zip([
		SE_BACKUP_NAME,
		SE_RESTORE_NAME,
		SE_TAKE_OWNERSHIP_NAME,
		SE_MANAGE_VOLUME_NAME,
	]) {
		let mut luid = LUID::default();
		// SAFETY: The SDK name is a static NUL-terminated UTF-16 string. A null
		// system name requests local lookup. The initialized output is writable.
		if unsafe { LookupPrivilegeValueW(null(), name, &mut luid) } == 0 {
			return Err(Error::Unavailable);
		}
		*entry = (luid.LowPart, luid.HighPart);
	}

	let mut storage = NativeBytes([0; TOKEN_PRIVILEGES_BYTES as usize]);
	let mut written = 0;
	// SAFETY: The query borrows a live token, and the bounded native output
	// and its length are aligned, initialized and exclusively writable.
	let ok = unsafe {
		GetTokenInformation(
			handle.as_raw_handle(),
			TokenPrivileges,
			storage.0.as_mut_ptr().cast(),
			TOKEN_PRIVILEGES_BYTES,
			&mut written,
		)
	};
	if ok == 0 {
		return Err(Error::Unavailable);
	}
	let reported = storage
		.0
		.get(..written as usize)
		.ok_or(Error::Unavailable)?;
	match privileges::contains_enabled(reported, &disallowed, SE_PRIVILEGE_ENABLED) {
		Some(true) => Err(Error::Unsupported),
		Some(false) => Ok(()),
		None => Err(Error::Unavailable),
	}
}

fn token_user(handle: BorrowedHandle<'_>) -> Result<Vec<u8>, Error> {
	let mut storage = NativeBytes([0; TOKEN_USER_BYTES as usize]);
	let mut written = 0;
	// SAFETY: This bounded native buffer is aligned, initialized and writable.
	// The token output is used only after successful class/length validation.
	let ok = unsafe {
		GetTokenInformation(
			handle.as_raw_handle(),
			TokenUser,
			storage.0.as_mut_ptr().cast(),
			TOKEN_USER_BYTES,
			&mut written,
		)
	};
	let received = storage
		.0
		.get(..written as usize)
		.ok_or(Error::Unavailable)?;
	if ok == 0 || received.len() < size_of::<TOKEN_USER>() {
		return Err(Error::Unavailable);
	}
	// SAFETY: The verified prefix is large enough for TOKEN_USER. Its integer
	// fields and raw SID pointer can be copied without dereferencing it.
	let user = unsafe { ptr::read_unaligned(received.as_ptr().cast::<TOKEN_USER>()) };
	let offset = user
		.User
		.Sid
		.addr()
		.checked_sub(received.as_ptr().addr())
		.filter(|offset| *offset >= size_of::<TOKEN_USER>())
		.ok_or(Error::Unavailable)?;
	let sid = received
		.get(offset..)
		.and_then(acl::sid)
		.ok_or(Error::Unavailable)?;
	Ok(sid.to_vec())
}

pub(super) fn descriptor(handle: BorrowedHandle<'_>) -> Result<Vec<u8>, Error> {
	let mut storage = NativeBytes([0; MAX_SECURITY_BYTES as usize]);
	let mut written = 0;
	// SAFETY: The held object is live and opened for READ_CONTROL. The
	// initialized output and count are writable through this bounded call.
	let ok = unsafe {
		GetKernelObjectSecurity(
			handle.as_raw_handle(),
			OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
			storage.0.as_mut_ptr().cast(),
			MAX_SECURITY_BYTES,
			&mut written,
		)
	};
	if ok == 0 {
		return Err(Error::Unavailable);
	}
	storage
		.0
		.get(..written as usize)
		.map(<[u8]>::to_vec)
		.ok_or(Error::Unavailable)
}
