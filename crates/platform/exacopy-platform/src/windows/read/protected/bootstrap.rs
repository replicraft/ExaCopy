use std::fs::File;
use std::io::{self, Read};
use std::os::windows::fs::FileExt as _;
use std::os::windows::io::{AsHandle as _, BorrowedHandle, OwnedHandle};

use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_NORMAL};

use crate::windows::{WindowsStageIdentity, native::observe};

use super::{
	Binding, DIRECTORY_ACCESS, Directory, DrivePath, Error, FILE_METADATA_ACCESS, FILE_READ_DATA,
	Kind, LeafStamp, WindowsComponent, acl, hold_root, named_identity, observe_fixed_root,
	observe_leaf, open_relative, read_at, refused, security,
};

const MAX_RECORD_BYTES: usize = 4096;

/// Expected native kind of a held fixture or provisioned bootstrap role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsBootstrapRoleKind {
	/// A real directory.
	Directory,
	/// A regular file.
	RegularFile,
}

/// Observes a held role's identity on the selected fixed NTFS drive.
///
/// The caller retains the original role handle, chooses the trusted drive and
/// maintains provisioning custody. The returned value carries only identity.
///
/// # Errors
/// Refuses an invalid drive letter, unavailable volume or mismatched native kind.
pub fn observe_windows_bootstrap_role_identity(
	drive_letter: u8,
	handle: BorrowedHandle<'_>,
	kind: WindowsBootstrapRoleKind,
) -> Result<WindowsStageIdentity, Error> {
	if !drive_letter.is_ascii_alphabetic() {
		return Err(Error::InvalidPath);
	}
	let root = hold_root(drive_letter)?;
	let kind = match kind {
		WindowsBootstrapRoleKind::Directory => Kind::Directory,
		WindowsBootstrapRoleKind::RegularFile => Kind::RegularFile,
	};
	let identity = observe(handle, kind).map_err(refused)?;
	super::super::same_volume(identity, root.identity).map_err(refused)?;
	Ok(identity)
}

/// The independently selected root identity for the read-only bootstrap scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsBootstrapRootSelection {
	/// The exact canonical lowercase ASCII volume GUID.
	pub volume_guid: [u8; 36],
	/// The exact native volume serial.
	pub volume_serial: u64,
	/// The exact native root object ID.
	pub file_id: [u8; 16],
}

/// Exact components and nonzero record lengths supplied by the selected layout.
#[derive(Clone, Copy, Debug)]
pub struct WindowsBootstrapLayout<'name> {
	/// The independently selected job directory component.
	pub job: WindowsComponent<'name>,
	/// The owner record component under the job.
	pub owner: WindowsComponent<'name>,
	/// The journal directory component under the job.
	pub journal: WindowsComponent<'name>,
	/// The first segment component under the journal directory.
	pub first_segment: WindowsComponent<'name>,
	/// The exact owner record extent, up to 4096 bytes.
	pub owner_bytes: usize,
	/// The exact first segment extent, up to 4096 bytes.
	pub first_segment_bytes: usize,
}

/// Native identity observations of the five held roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsBootstrapRoleObservations {
	/// The admitted container root.
	pub root: WindowsStageIdentity,
	/// The job directory.
	pub job_directory: WindowsStageIdentity,
	/// The owner record.
	pub owner_file: WindowsStageIdentity,
	/// The journal directory.
	pub journal_directory: WindowsStageIdentity,
	/// The first segment.
	pub first_segment: WindowsStageIdentity,
}

/// Held read-only bootstrap record scope on a protected fixed NTFS root.
///
/// The caller selects the root identity and exact layout from independent
/// trusted configuration. The caller trusts the kernel, storage and namespace
/// administrators, LocalSystem, principals with equivalent privilege, and
/// cooperating processes acting as the current user. Independent provisioning
/// must exclude previously retained untrusted mutation capabilities throughout
/// the held ancestry and roles. The caller must ensure the trusted participants
/// refrain from changing names, data, streams, ownership or ACLs during the
/// inspection. The share modes supplement these custody conditions.
/// All results describe live observations and may include access-time changes.
pub struct WindowsBootstrapRecords<'name> {
	subject: security::Subject,
	path: DrivePath<'name>,
	ancestors: Vec<Directory>,
	layout: WindowsBootstrapLayout<'name>,
	root: Directory,
	job: Directory,
	journal: Directory,
	owner: Record,
	segment: Record,
}

impl<'name> WindowsBootstrapRecords<'name> {
	/// Opens exact protected roles beneath a counted absolute drive path.
	///
	/// Both record metadata pins are admitted before requesting any record data
	/// access. The returned scope keeps the pins, data handles, named roles and
	/// protected ancestry held through the final read.
	///
	/// # Errors
	/// Refuses inadmissible actor, path, ACL, identity, extent, stream inventory or I/O.
	pub fn open(
		root_path: &'name [u16],
		expected: WindowsBootstrapRootSelection,
		layout: WindowsBootstrapLayout<'name>,
	) -> Result<Self, Error> {
		for length in [layout.owner_bytes, layout.first_segment_bytes] {
			if length == 0 || length > MAX_RECORD_BYTES {
				return Err(Error::TooLarge);
			}
		}
		let path = DrivePath::parse(root_path).map_err(|_| Error::InvalidPath)?;
		let subject = security::Subject::current()?;
		let volume = hold_root(path.letter)?;
		let binding = Binding::capture(
			volume.handle.as_handle(),
			volume.identity,
			&subject,
			acl::Role::UpperDirectory,
		)?;
		let mut ancestors = vec![Directory {
			handle: volume.handle,
			binding,
		}];
		for &name in &path.parents {
			let directory =
				open_directory(last(&ancestors)?, name, &subject, acl::Role::UpperDirectory)?;
			ancestors.push(directory);
		}
		let root = open_directory(last(&ancestors)?, path.leaf, &subject, acl::Role::Private)?;
		let observed = root.binding.identity;
		if observed.volume_guid() != expected.volume_guid
			|| observed.volume_serial() != expected.volume_serial
			|| observed.file_id() != expected.file_id
		{
			return Err(Error::Changed);
		}
		let job = open_directory(&root, layout.job, &subject, acl::Role::Private)?;
		let journal = open_directory(&job, layout.journal, &subject, acl::Role::Private)?;
		let owner = MetadataPin::open(&job, layout.owner, &subject, layout.owner_bytes)?;
		let segment = MetadataPin::open(
			&journal,
			layout.first_segment,
			&subject,
			layout.first_segment_bytes,
		)?;
		let roles = [
			observed,
			job.binding.identity,
			journal.binding.identity,
			owner.binding.identity,
			segment.binding.identity,
		];
		for (index, role) in roles.iter().enumerate() {
			if roles[..index].contains(role) {
				return Err(Error::Unprotected);
			}
		}
		let owner = owner.open_data(&job, layout.owner)?;
		let segment = segment.open_data(&journal, layout.first_segment)?;
		let records = Self {
			subject,
			path,
			ancestors,
			layout,
			root,
			job,
			journal,
			owner,
			segment,
		};
		records.recheck()?;
		Ok(records)
	}

	/// Returns the held identities as values for the independent storage codec.
	#[must_use]
	pub fn roles(&self) -> WindowsBootstrapRoleObservations {
		WindowsBootstrapRoleObservations {
			root: self.root.binding.identity,
			job_directory: self.job.binding.identity,
			owner_file: self.owner.pin.binding.identity,
			journal_directory: self.journal.binding.identity,
			first_segment: self.segment.pin.binding.identity,
		}
	}

	/// Compares two complete bounded reads of the owner and checks physical EOF.
	///
	/// # Errors
	/// Refuses a changed role, incomplete read, mismatched readback or unconfirmed EOF.
	pub fn read_owner(&mut self) -> Result<Vec<u8>, Error> {
		self.recheck()?;
		let mut bytes = vec![0; self.owner.pin.stamp.length];
		let mut readback = vec![0; bytes.len()];
		read_at(&self.owner.file, 0, &mut bytes)?;
		self.owner.eof()?;
		self.recheck()?;
		read_at(&self.owner.file, 0, &mut readback)?;
		self.owner.eof()?;
		self.recheck()?;
		if bytes != readback {
			return Err(Error::Changed);
		}
		Ok(bytes)
	}

	/// Starts a first-segment reader at byte zero while retaining this entire scope.
	#[must_use]
	pub fn first_segment(&mut self) -> WindowsBootstrapSegment<'_, 'name> {
		WindowsBootstrapSegment {
			records: self,
			offset: 0,
			terminal: false,
			failed: false,
		}
	}

	fn recheck(&self) -> Result<(), Error> {
		if security::Subject::current()? != self.subject {
			return Err(Error::Changed);
		}
		let volume = self.ancestors.first().ok_or(Error::Changed)?;
		let reopened = hold_root(self.path.letter)?;
		let held = volume.handle.as_handle();
		volume
			.binding
			.recheck(held, observe_fixed_root(held).map_err(super::root_error)?)?;
		volume
			.binding
			.recheck(reopened.handle.as_handle(), reopened.identity)?;
		for (pair, &name) in self.ancestors.windows(2).zip(&self.path.parents) {
			let [parent, child] = pair else {
				return Err(Error::Changed);
			};
			check_directory(parent, child, name)?;
		}
		check_directory(last(&self.ancestors)?, &self.root, self.path.leaf)?;
		check_directory(&self.root, &self.job, self.layout.job)?;
		check_directory(&self.job, &self.journal, self.layout.journal)?;
		self.owner.check(&self.job, self.layout.owner)?;
		self.segment
			.check(&self.journal, self.layout.first_segment)?;
		if security::Subject::current()? != self.subject {
			return Err(Error::Changed);
		}
		Ok(())
	}
}

fn last(ancestors: &[Directory]) -> Result<&Directory, Error> {
	ancestors.last().ok_or(Error::Changed)
}

fn open_directory(
	parent: &Directory,
	name: WindowsComponent<'_>,
	subject: &security::Subject,
	role: acl::Role,
) -> Result<Directory, Error> {
	let handle = open_relative(
		parent.handle.as_handle(),
		name,
		Kind::Directory,
		DIRECTORY_ACCESS,
	)?;
	let identity = named_identity(handle.as_handle(), Kind::Directory, name)?;
	super::super::same_volume(identity, parent.binding.identity).map_err(refused)?;
	let binding = Binding::capture(handle.as_handle(), identity, subject, role)?;
	Ok(Directory { handle, binding })
}

fn check_directory(
	parent: &Directory,
	child: &Directory,
	name: WindowsComponent<'_>,
) -> Result<(), Error> {
	let named = open_relative(
		parent.handle.as_handle(),
		name,
		Kind::Directory,
		DIRECTORY_ACCESS,
	)?;
	for handle in [child.handle.as_handle(), named.as_handle()] {
		child
			.binding
			.recheck(handle, named_identity(handle, Kind::Directory, name)?)?;
	}
	Ok(())
}

struct MetadataPin {
	handle: OwnedHandle,
	binding: Binding,
	stamp: LeafStamp,
}

impl MetadataPin {
	fn open(
		parent: &Directory,
		name: WindowsComponent<'_>,
		subject: &security::Subject,
		extent: usize,
	) -> Result<Self, Error> {
		let handle = open_relative(
			parent.handle.as_handle(),
			name,
			Kind::RegularFile,
			FILE_METADATA_ACCESS,
		)?;
		let (binding, stamp) = observe_leaf(handle.as_handle(), name, subject)?;
		super::super::same_volume(binding.identity, parent.binding.identity).map_err(refused)?;
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
		})
	}

	fn open_data(self, parent: &Directory, name: WindowsComponent<'_>) -> Result<Record, Error> {
		let file = open_relative(
			parent.handle.as_handle(),
			name,
			Kind::RegularFile,
			FILE_METADATA_ACCESS | FILE_READ_DATA,
		)?;
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

struct Record {
	pin: MetadataPin,
	file: File,
}

impl Record {
	fn check(&self, parent: &Directory, name: WindowsComponent<'_>) -> Result<(), Error> {
		let named = open_relative(
			parent.handle.as_handle(),
			name,
			Kind::RegularFile,
			FILE_METADATA_ACCESS,
		)?;
		for handle in [
			self.pin.handle.as_handle(),
			self.file.as_handle(),
			named.as_handle(),
		] {
			self.pin.check_handle(handle, name)?;
		}
		Ok(())
	}

	fn eof(&self) -> Result<(), Error> {
		match self.file.seek_read(&mut [0], self.pin.stamp.length as u64) {
			Ok(0) => Ok(()),
			Ok(_) => Err(Error::Changed),
			Err(error) => Err(super::io_error(&error)),
		}
	}
}

/// Sequential, exact-extent reader over the held first segment.
pub struct WindowsBootstrapSegment<'scope, 'name> {
	records: &'scope mut WindowsBootstrapRecords<'name>,
	offset: usize,
	terminal: bool,
	failed: bool,
}

impl WindowsBootstrapSegment<'_, '_> {
	/// Confirms terminal physical EOF and reobserves the exact five held roles.
	///
	/// # Errors
	/// Refuses a failed reader, an unread terminal byte, or any failed final observation.
	pub fn finish(self) -> Result<(), Error> {
		if self.failed || !self.terminal || self.offset != self.records.segment.pin.stamp.length {
			return Err(Error::Changed);
		}
		self.records.recheck()?;
		self.records.owner.eof()?;
		self.records.segment.eof()?;
		self.records.recheck()
	}

	fn read_checked(&mut self, output: &mut [u8]) -> Result<usize, Error> {
		if self.failed {
			return Err(Error::Changed);
		}
		self.records.recheck()?;
		let segment = &self.records.segment;
		let length = segment.pin.stamp.length;
		if self.offset == length {
			segment.eof()?;
			self.records.recheck()?;
			self.terminal = true;
			return Ok(0);
		}
		let count = output.len().min(length - self.offset);
		read_at(&segment.file, self.offset as u64, &mut output[..count])?;
		self.records.recheck()?;
		self.offset += count;
		Ok(count)
	}
}

impl Read for WindowsBootstrapSegment<'_, '_> {
	fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
		if output.is_empty() {
			return Ok(0);
		}
		let outcome = self.read_checked(output);
		if outcome.is_err() {
			self.failed = true;
			self.terminal = false;
		}
		outcome.map_err(io::Error::other)
	}
}
