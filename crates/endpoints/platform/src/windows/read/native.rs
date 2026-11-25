use std::os::windows::io::BorrowedHandle;

use windows_sys::Win32::Storage::FileSystem::{
	FILE_BASIC_INFO, FILE_NAME_NORMALIZED, FileBasicInfo, FileStandardInfo, GetDriveTypeW,
};

use super::ReadError;
use crate::windows::native::{
	Kind, ObjectId, Refusal, StandardInformation, local_ntfs_path, observe_file, parse_volume_guid,
	query,
};

pub(super) fn ensure_fixed_drive(terminated_root: &[u16]) -> Result<(), ReadError> {
	// GetDriveTypeW reports this value for a root backed by a fixed drive.
	const DRIVE_FIXED: u32 = 3;
	if terminated_root
		.split_last()
		.is_none_or(|(&last, prefix)| last != 0 || prefix.is_empty() || prefix.contains(&0))
	{
		return Err(ReadError::Native(Refusal::UnidentifiedVolume));
	}
	// SAFETY: A single trailing nul terminates the nonempty live wide root buffer.
	if unsafe { GetDriveTypeW(terminated_root.as_ptr()) } != DRIVE_FIXED {
		return Err(ReadError::NotFixedDrive);
	}
	Ok(())
}

pub(super) fn observe_fixed_root(handle: BorrowedHandle<'_>) -> Result<ObjectId, ReadError> {
	let info = observe_file(handle, Kind::Directory).map_err(ReadError::Native)?;
	// A physical volume root uses only "\\?\Volume{uuid}\" and its terminating nul.
	const VOLUME_ROOT_UNITS: usize = 50;
	let mut path = [0_u16; VOLUME_ROOT_UNITS];
	let count =
		local_ntfs_path(handle, FILE_NAME_NORMALIZED, &mut path).map_err(ReadError::Native)?;
	let (volume, remainder) = parse_volume_guid(&path[..count]).map_err(ReadError::Native)?;
	if !remainder.is_empty() {
		return Err(ReadError::NotVolumeRoot);
	}
	ensure_fixed_drive(&path[..=count])?;
	Ok(ObjectId {
		volume,
		volume_serial: info.VolumeSerialNumber,
		file_id: info.FileId.Identifier,
	})
}

pub(super) fn comparison_information(
	handle: BorrowedHandle<'_>,
) -> Result<(StandardInformation, FILE_BASIC_INFO), Refusal> {
	let mut standard = StandardInformation::default();
	let mut basic = FILE_BASIC_INFO::default();
	// SAFETY: Both classes match their initialized writable native output types.
	unsafe {
		query(handle, FileStandardInfo, &mut standard)?;
		query(handle, FileBasicInfo, &mut basic)?;
	}
	Ok((standard, basic))
}
