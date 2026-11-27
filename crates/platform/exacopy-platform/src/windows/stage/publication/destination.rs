use std::os::windows::io::{AsHandle as _, BorrowedHandle, OwnedHandle};

use windows_sys::Wdk::Storage::FileSystem::{FILE_CREATE, FILE_OPEN};
use windows_sys::Win32::Foundation::{OBJ_DONT_REPARSE, STATUS_OBJECT_NAME_COLLISION};
use windows_sys::Win32::Storage::FileSystem::{
	FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES,
	FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, READ_CONTROL, SYNCHRONIZE,
};

use super::{WindowsPublicationError, metadata, native};
use crate::windows::WindowsComponent;
use crate::windows::native::{
	Kind, ObjectId, Refusal, RelativeFileOpen, observe, observe_entry, open_relative_entry,
	open_relative_entry_observed,
};
use crate::windows::stage::{FILE_CREATED_INFORMATION, FILE_OPENED_INFORMATION};

const DESTINATION_ACCESS: u32 = FILE_ADD_FILE
	| FILE_LIST_DIRECTORY
	| FILE_TRAVERSE
	| FILE_READ_ATTRIBUTES
	| READ_CONTROL
	| SYNCHRONIZE;

/// Already held and authorized outer directory for creating a fresh experimental destination.
///
/// The caller supplies a directory held without delete sharing, proves its
/// controlled root and ancestor provenance, and excludes earlier or
/// competing mutation rights in that controlled scope. This capability
/// observes existing rights and never upgrades a read-only handle.
pub struct WindowsPublicationRoot<'root> {
	handle: BorrowedHandle<'root>,
	identity: ObjectId,
	security: Vec<u8>,
}

impl<'root> WindowsPublicationRoot<'root> {
	/// Binds a held fixed-NTFS root with granted direct subdirectory creation.
	///
	/// # Errors
	/// Refuses unsupported volumes, a changed directory or insufficient rights.
	pub fn from_authorized_handle(
		handle: BorrowedHandle<'root>,
	) -> Result<Self, WindowsPublicationError> {
		let identity = observe(handle, Kind::Directory).map_err(WindowsPublicationError::native)?;
		native::require_fixed_ntfs(handle)?;
		native::require_access(handle, FILE_ADD_SUBDIRECTORY | READ_CONTROL)?;
		let security = metadata::descriptor(handle)?;
		Ok(Self {
			handle,
			identity,
			security,
		})
	}

	/// Exclusively creates a new held destination directory for one rename.
	///
	/// The caller maintains custody until the attempt ends. Authorized
	/// participants may only create a new incumbent; they must never delete,
	/// rename in, or reuse entries in the directory, or change parents,
	/// objects or metadata. A new directory and continuous custody exclude
	/// historical target names that can tunnel creation time or spelling.
	/// Sharing flags alone cannot exclude attribute, ACL, owner or ADS effects.
	///
	/// # Errors
	/// Refuses an occupied directory, failed observations or uncertain
	/// creation. Any possibly created object remains for reconciliation.
	pub fn create_destination<'destination>(
		&'destination self,
		name: WindowsComponent<'destination>,
	) -> Result<WindowsPublicationDestination<'destination>, WindowsPublicationError> {
		self.check()?;
		let (handle, information) = match open_relative_entry_observed(
			self.handle,
			name,
			RelativeFileOpen {
				access: DESTINATION_ACCESS,
				share: FILE_SHARE_READ | FILE_SHARE_WRITE,
				disposition: FILE_CREATE,
				attributes: OBJ_DONT_REPARSE,
				expected_result: None,
			},
			Kind::Directory,
		) {
			Ok(opened) => opened,
			Err(Refusal::OpenFailed(STATUS_OBJECT_NAME_COLLISION)) => {
				return Err(WindowsPublicationError::DestinationOccupied);
			}
			Err(cause) => {
				return Err(WindowsPublicationError::destination_creation_uncertain(
					cause,
				));
			}
		};
		let mut retained = WindowsUnconfirmedPublicationDirectory {
			handle,
			identity: None,
			information,
		};
		let confirmation = self.confirm_child(name, &mut retained);
		match confirmation {
			Ok((identity, security)) => Ok(WindowsPublicationDestination {
				root: self,
				handle: retained.handle,
				name,
				identity,
				security,
			}),
			Err(cause) => Err(WindowsPublicationError::DestinationCreatedUnconfirmed {
				retained,
				cause: Box::new(cause),
			}),
		}
	}

	fn check(&self) -> Result<(), WindowsPublicationError> {
		check_parent(self.handle, None, self.identity, &self.security)
	}

	fn confirm_child(
		&self,
		name: WindowsComponent<'_>,
		retained: &mut WindowsUnconfirmedPublicationDirectory,
	) -> Result<(ObjectId, Vec<u8>), WindowsPublicationError> {
		if retained.information != FILE_CREATED_INFORMATION {
			return Err(WindowsPublicationError::native(
				Refusal::UnexpectedOpenResult(retained.information),
			));
		}
		let handle = retained.handle.as_handle();
		let identity = observe_entry(handle, Kind::Directory, Some(name))
			.map_err(WindowsPublicationError::native)?;
		retained.identity = Some(identity);
		if identity == self.identity
			|| identity.volume != self.identity.volume
			|| identity.volume_serial != self.identity.volume_serial
		{
			return Err(WindowsPublicationError::ParentScope);
		}
		native::require_access(handle, FILE_ADD_FILE | READ_CONTROL)?;
		let security = metadata::descriptor(handle)?;
		check_parent(handle, Some(name), identity, &security)?;
		self.check()?;
		Ok((identity, security))
	}
}

/// A newly created destination parent with one-use experimental rename authority.
pub struct WindowsPublicationDestination<'parent> {
	root: &'parent WindowsPublicationRoot<'parent>,
	handle: OwnedHandle,
	name: WindowsComponent<'parent>,
	identity: ObjectId,
	security: Vec<u8>,
}

impl WindowsPublicationDestination<'_> {
	pub(super) fn check(&self) -> Result<(), WindowsPublicationError> {
		self.root.check()?;
		check_parent(
			self.handle(),
			Some(self.name),
			self.identity,
			&self.security,
		)?;
		let named = open_relative_entry(
			self.root.handle,
			self.name,
			RelativeFileOpen {
				access: FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
				share: FILE_SHARE_READ | FILE_SHARE_WRITE,
				disposition: FILE_OPEN,
				attributes: OBJ_DONT_REPARSE,
				expected_result: Some(FILE_OPENED_INFORMATION),
			},
			Kind::Directory,
		)
		.map_err(WindowsPublicationError::native)?;
		check_parent(
			named.as_handle(),
			Some(self.name),
			self.identity,
			&self.security,
		)
	}

	pub(super) fn handle(&self) -> BorrowedHandle<'_> {
		self.handle.as_handle()
	}

	pub(super) const fn identity(&self) -> ObjectId {
		self.identity
	}
}

/// Held evidence when exclusive destination creation cannot be confirmed.
#[derive(Debug)]
pub struct WindowsUnconfirmedPublicationDirectory {
	handle: OwnedHandle,
	identity: Option<ObjectId>,
	information: usize,
}

impl WindowsUnconfirmedPublicationDirectory {
	/// Returns any native directory identity observed after creation.
	#[must_use]
	pub const fn identity(&self) -> Option<ObjectId> {
		self.identity
	}

	/// Returns the raw information value supplied by the native create.
	#[must_use]
	pub const fn native_information(&self) -> usize {
		self.information
	}
}

fn check_parent(
	handle: BorrowedHandle<'_>,
	name: Option<WindowsComponent<'_>>,
	identity: ObjectId,
	security: &[u8],
) -> Result<(), WindowsPublicationError> {
	if observe_entry(handle, Kind::Directory, name).map_err(WindowsPublicationError::native)?
		!= identity
		|| metadata::descriptor(handle)? != security
	{
		return Err(WindowsPublicationError::ParentChanged);
	}
	Ok(())
}
