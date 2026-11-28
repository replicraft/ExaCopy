use std::fs::File;
use std::os::windows::fs::FileExt as _;
use std::os::windows::io::{AsHandle as _, BorrowedHandle, OwnedHandle};

use windows_sys::Wdk::Storage::FileSystem::FILE_OPEN;
use windows_sys::Win32::Foundation::{GENERIC_WRITE, OBJ_DONT_REPARSE};
use windows_sys::Win32::Storage::FileSystem::{
	FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
};

use super::super::{
	Binding, Directory, Error, FILE_METADATA_ACCESS, FILE_OPENED_INFORMATION, FILE_READ_DATA, Kind,
	LeafStamp, WindowsComponent, named_identity, observe_leaf, open_relative_entry, refused,
	security,
};
use crate::windows::native::RelativeFileOpen;

pub(super) struct MetadataPin {
	handle: OwnedHandle,
	pub(super) binding: Binding,
	pub(super) stamp: LeafStamp,
	share: u32,
}

impl MetadataPin {
	pub(super) fn open(
		parent: &Directory,
		name: WindowsComponent<'_>,
		subject: &security::Subject,
		extent: usize,
		share: u32,
	) -> Result<Self, Error> {
		let handle = open(parent, name, FILE_METADATA_ACCESS, share)?;
		let (binding, stamp) = observe_leaf(handle.as_handle(), name, subject)?;
		super::super::super::same_volume(binding.identity, parent.binding.identity)
			.map_err(refused)?;
		let supported = FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NORMAL;
		if stamp.attributes == 0 || stamp.attributes & !supported != 0 {
			return Err(Error::Unprotected);
		}
		if stamp.length != extent {
			return Err(Error::Changed);
		}
		stamp.check_stream(handle.as_handle(), Error::Unprotected)?;
		Ok(Self {
			handle,
			binding,
			stamp,
			share,
		})
	}

	pub(super) fn open_data(
		self,
		parent: &Directory,
		name: WindowsComponent<'_>,
		write: bool,
	) -> Result<Record, Error> {
		let access = FILE_METADATA_ACCESS | FILE_READ_DATA;
		let file = if write {
			open(parent, name, access | GENERIC_WRITE, 0)?
		} else {
			open(parent, name, access, FILE_SHARE_READ)?
		};
		self.check_handle(file.as_handle(), name)?;
		Ok(Record {
			pin: self,
			file: file.into(),
		})
	}

	fn check_handle(
		&self,
		handle: BorrowedHandle<'_>,
		name: WindowsComponent<'_>,
	) -> Result<(), Error> {
		let identity = named_identity(handle, Kind::RegularFile, name)?;
		self.binding.recheck(handle, identity)?;
		if LeafStamp::capture(handle)? != self.stamp {
			return Err(Error::Changed);
		}
		self.stamp.check_stream(handle, Error::Changed)
	}
}

pub(super) struct Record {
	pub(super) pin: MetadataPin,
	pub(super) file: File,
}

impl Record {
	// Only a successful bounded write on this original handle can advance the
	// expected data stamps. The independent named/pin checks follow this step.
	pub(super) fn confirm_write(
		&mut self,
		name: WindowsComponent<'_>,
		end: usize,
	) -> Result<(), Error> {
		let handle = self.file.as_handle();
		let identity = named_identity(handle, Kind::RegularFile, name)?;
		self.pin.binding.recheck(handle, identity)?;
		let before = self.pin.stamp;
		let after = LeafStamp::capture(handle)?;
		let supported_transition = after.attributes == before.attributes
			|| (before.attributes == FILE_ATTRIBUTE_NORMAL
				&& after.attributes == FILE_ATTRIBUTE_ARCHIVE);
		if after.length != end
			|| after.creation_time != before.creation_time
			|| !supported_transition
		{
			return Err(Error::Changed);
		}
		after.check_stream(handle, Error::Changed)?;
		self.pin.stamp = after;
		Ok(())
	}

	pub(super) fn check(
		&self,
		parent: &Directory,
		name: WindowsComponent<'_>,
	) -> Result<(), Error> {
		let named = open(parent, name, FILE_METADATA_ACCESS, self.pin.share)?;
		for handle in [
			self.pin.handle.as_handle(),
			self.file.as_handle(),
			named.as_handle(),
		] {
			self.pin.check_handle(handle, name)?;
		}
		Ok(())
	}

	pub(super) fn eof(&self) -> Result<(), Error> {
		match self.file.seek_read(&mut [0], self.pin.stamp.length as u64) {
			Ok(0) => Ok(()),
			Ok(_) => Err(Error::Changed),
			Err(error) => Err(super::super::io_error(&error)),
		}
	}
}

fn open(
	parent: &Directory,
	name: WindowsComponent<'_>,
	access: u32,
	share: u32,
) -> Result<OwnedHandle, Error> {
	open_relative_entry(
		parent.handle.as_handle(),
		name,
		RelativeFileOpen {
			access,
			share,
			disposition: FILE_OPEN,
			attributes: OBJ_DONT_REPARSE,
			expected_result: Some(FILE_OPENED_INFORMATION),
		},
		Kind::RegularFile,
	)
	.map_err(refused)
}
