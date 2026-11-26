//! Metadata-only observations of one literal lookup under an authorized held parent.

use std::fmt;
use std::num::NonZeroU64;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use exacopy_endpoint::UnixComponent;
use rustix::fs::{self, FileType, Mode, OFlags};
use rustix::io::Errno;

use super::FileIdentity;
use super::handle::mount_id_no_follow;
use super::stage::CHILD_RESOLVE;

#[cfg(test)]
mod tests;

/// Identity of a live native object and the mount used to observe it.
///
/// Object equality detects hard-linked names while pins remain held. Mount
/// equality describes lookup context and is distinct from object equality or
/// proof of an eligible physical filesystem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedIdentity {
	object: FileIdentity,
	mount: NonZeroU64,
}

impl ObservedIdentity {
	/// Returns the live device and inode identity.
	#[must_use]
	pub const fn object(self) -> FileIdentity {
		self.object
	}

	/// Returns the lookup's namespace-local Linux mount ID.
	#[must_use]
	pub const fn mount(self) -> NonZeroU64 {
		self.mount
	}
}

/// Observable kind of the entry itself, without reading its payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EntryKind {
	/// A regular file.
	Regular,
	/// A directory observed without walking its children.
	Directory,
	/// A symbolic link observed without following its referent.
	Symlink,
	/// Another entry kind, such as a FIFO, device or socket.
	Other,
}

/// A bounded native observation could not establish the requested fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ObserveError {
	/// The supplied parent is not a live directory.
	InvalidParent,
	/// Native object or mount identity is missing.
	UnavailableIdentity,
	/// The filesystem did not establish a known entry kind.
	UnavailableKind,
	/// The lookup encountered a different mount or device.
	CrossedMount,
	/// The held parent or originally observed child failed revalidation.
	Changed,
	/// Native support was missing or a filesystem operation failed.
	Io(Errno),
}

impl fmt::Display for ObserveError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidParent => formatter.write_str("slot parent is not a live directory"),
			Self::UnavailableIdentity => formatter.write_str("native slot identity is unavailable"),
			Self::UnavailableKind => formatter.write_str("native slot entry kind is unavailable"),
			Self::CrossedMount => formatter.write_str("slot lookup crossed a mount"),
			Self::Changed => formatter.write_str("held slot observation changed"),
			Self::Io(error) => write!(formatter, "native slot observation failed ({error})"),
		}
	}
}

impl std::error::Error for ObserveError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Io(error) => Some(error),
			_ => None,
		}
	}
}

impl From<Errno> for ObserveError {
	fn from(error: Errno) -> Self {
		Self::Io(error)
	}
}

/// One raw component under a caller-authorized directory descriptor.
///
/// A successful lookup supplies a live observation only. Parent path
/// provenance, private namespace isolation, native name equivalence, filesystem
/// eligibility and the semantics of any future relocation require separate checks.
pub struct HeldSlot<'scope> {
	parent: BorrowedFd<'scope>,
	parent_identity: ObservedIdentity,
	name: UnixComponent<'scope>,
}

impl fmt::Debug for HeldSlot<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.debug_struct("HeldSlot").finish_non_exhaustive()
	}
}

impl<'scope> HeldSlot<'scope> {
	/// Binds a single lookup under the already authorized parent.
	///
	/// # Errors
	/// Rejects a non-directory, unlinked directory or incomplete native identity.
	pub fn from_authorized_parent(
		parent: BorrowedFd<'scope>,
		name: UnixComponent<'scope>,
	) -> Result<Self, ObserveError> {
		Ok(Self {
			parent,
			parent_identity: observe_parent(parent)?,
			name,
		})
	}

	/// Returns the held parent's comparison identity.
	#[must_use]
	pub const fn parent_identity(&self) -> ObservedIdentity {
		self.parent_identity
	}

	/// Observes the selected lookup without following a link or opening payload bytes.
	///
	/// Lookup uses the mounted filesystem's name equivalence. An absence is a
	/// point observation and may become stale immediately.
	///
	/// # Errors
	/// Reports stale or invalid parent, mount crossings, and native lookup
	/// failures separately from observed absence.
	pub fn observe(&self) -> Result<SlotObservation<'_, 'scope>, ObserveError> {
		self.recheck_parent()?;
		let fd = fs::openat2(
			self.parent,
			self.name.as_bytes(),
			OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
			Mode::empty(),
			CHILD_RESOLVE,
		);
		let observation = match fd {
			Ok(fd) => {
				let stat = fs::fstat(&fd)?;
				let identity = observe_identity(fd.as_fd(), &stat)?;
				if identity.mount != self.parent_identity.mount
					|| identity.object.device() != self.parent_identity.object.device()
				{
					return Err(ObserveError::CrossedMount);
				}
				SlotObservation::Present(PinnedEntry {
					slot: self,
					fd,
					identity,
					kind: entry_kind(FileType::from_raw_mode(stat.st_mode))?,
				})
			}
			Err(Errno::NOENT) => SlotObservation::Absent,
			Err(Errno::XDEV) => return Err(ObserveError::CrossedMount),
			Err(error) => return Err(error.into()),
		};
		self.recheck_parent()?;
		Ok(observation)
	}

	fn recheck_parent(&self) -> Result<(), ObserveError> {
		if observe_parent(self.parent)? != self.parent_identity {
			return Err(ObserveError::Changed);
		}
		Ok(())
	}
}

/// Outcome of one bounded live name lookup.
#[derive(Debug)]
pub enum SlotObservation<'slot, 'scope> {
	/// The selected name resolved to no entry at lookup.
	Absent,
	/// The selected name resolved to this independently held metadata pin.
	Present(PinnedEntry<'slot, 'scope>),
}

/// An observation of one selected name and its pinned native object.
///
/// The pin has metadata-only rights and exposes neither descriptors nor payload.
/// The observed binding can still change as soon as a lookup returns.
pub struct PinnedEntry<'slot, 'scope> {
	slot: &'slot HeldSlot<'scope>,
	fd: OwnedFd,
	identity: ObservedIdentity,
	kind: EntryKind,
}

impl fmt::Debug for PinnedEntry<'_, '_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("PinnedEntry")
			.field("kind", &self.kind)
			.finish_non_exhaustive()
	}
}

impl PinnedEntry<'_, '_> {
	/// Returns the object's live comparison identity.
	#[must_use]
	pub const fn identity(&self) -> ObservedIdentity {
		self.identity
	}

	/// Returns the observed entry's opaque kind.
	#[must_use]
	pub const fn kind(&self) -> EntryKind {
		self.kind
	}

	/// Independently looks up the original slot and checks current identity against the live pin.
	///
	/// # Errors
	/// Reports absence or a different object as changed. Lookup failures and
	/// uncertain identity remain errors rather than being classified as absence.
	pub fn recheck(&self) -> Result<(), ObserveError> {
		let stat = fs::fstat(&self.fd)?;
		if observe_identity(self.fd.as_fd(), &stat)? != self.identity
			|| entry_kind(FileType::from_raw_mode(stat.st_mode))? != self.kind
		{
			return Err(ObserveError::Changed);
		}
		match self.slot.observe()? {
			SlotObservation::Present(current)
				if current.identity == self.identity && current.kind == self.kind =>
			{
				Ok(())
			}
			_ => Err(ObserveError::Changed),
		}
	}
}

fn observe_parent(parent: BorrowedFd<'_>) -> Result<ObservedIdentity, ObserveError> {
	let stat = fs::fstat(parent)?;
	if FileType::from_raw_mode(stat.st_mode) != FileType::Directory || stat.st_nlink == 0 {
		return Err(ObserveError::InvalidParent);
	}
	observe_identity(parent, &stat)
}

fn observe_identity(fd: BorrowedFd<'_>, stat: &fs::Stat) -> Result<ObservedIdentity, ObserveError> {
	let object = FileIdentity::from_stat(stat);
	let mount =
		NonZeroU64::new(mount_id_no_follow(fd)?).ok_or(ObserveError::UnavailableIdentity)?;
	if object.inode() == 0 {
		return Err(ObserveError::UnavailableIdentity);
	}
	Ok(ObservedIdentity { object, mount })
}

fn entry_kind(kind: FileType) -> Result<EntryKind, ObserveError> {
	match kind {
		FileType::RegularFile => Ok(EntryKind::Regular),
		FileType::Directory => Ok(EntryKind::Directory),
		FileType::Symlink => Ok(EntryKind::Symlink),
		FileType::Fifo | FileType::Socket | FileType::CharacterDevice | FileType::BlockDevice => {
			Ok(EntryKind::Other)
		}
		_ => Err(ObserveError::UnavailableKind),
	}
}
