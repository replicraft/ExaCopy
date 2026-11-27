//! Held read-only observations for one subject under two sibling Linux roots.

use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::linux_staging::StagingSource as _;
use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags, Stat};
use rustix::io::Errno;

use super::handle::{FileIdentity, mount_id};
use super::{MountObservations, NamedReadView, ReadError, ReadRoot};

const DIRECTORY_FLAGS: OFlags = OFlags::PATH.union(OFlags::DIRECTORY).union(OFlags::CLOEXEC);
const NO_LINKS: ResolveFlags = ResolveFlags::NO_SYMLINKS.union(ResolveFlags::NO_MAGICLINKS);
const CHILD_RESOLUTION: ResolveFlags = NO_LINKS
	.union(ResolveFlags::BENEATH)
	.union(ResolveFlags::NO_XDEV);
const MAX_PARENT_PATH_BYTES: usize = 4095;
const ORDINARY_PERMISSION_BITS: u32 = 0o777;

mod history_members;
mod history_scope;
#[cfg(feature = "experimental-linux-managed-sync")]
mod managed;
#[cfg(feature = "experimental-linux-managed-sync")]
mod managed_mount;
mod names;
mod namespaces;
#[cfg(test)]
mod tests;

pub use history_members::{SyncHistoryDirectory, SyncHistoryReader};
pub use history_scope::SyncHistoryLocation;
#[cfg(feature = "experimental-linux-managed-sync")]
pub(in crate::linux) use history_scope::unique_mount_id;
#[cfg(feature = "experimental-linux-managed-sync")]
pub use managed::{
	ManagedSyncError, ManagedSyncExpectedObject, ManagedSyncExpectedRoot, ManagedSyncNativeScope,
	ManagedSyncPreviewPair, ManagedSyncReadLease,
};

/// Failure to obtain a complete live observation of the selected pair.
#[derive(Debug)]
#[non_exhaustive]
pub enum SyncPreviewError {
	/// Parent must be selected by a bounded absolute path without dot or empty components.
	InvalidParent,
	/// Held root identities are not distinct.
	AliasedRoots,
	/// The two names select the same held file.
	AliasedFiles,
	/// The parent mount is unavailable or outside the supported local profile.
	UnsupportedMount,
	/// The current mount or user namespace could not be verified through procfs.
	UnsupportedNamespace,
	/// The held directory uses encrypted or case-folded lookup semantics.
	UnsupportedHistoryNamePolicy,
	/// Exact native mount attributes were unavailable.
	#[cfg(feature = "experimental-linux-managed-sync")]
	UnsupportedHistoryMountAttributes,
	/// The held mount translates UID/GID values.
	#[cfg(feature = "experimental-linux-managed-sync")]
	IdMappedHistoryMount,
	/// Lookup did not correspond to an exact raw entry.
	NameAlias,
	/// The exact-name confirmation exceeded the bounded directory scan.
	DirectoryLimit,
	/// A previously observed name, mount, or selected object changed.
	Changed,
	/// A pinned file could not be read or revalidated.
	Read(ReadError),
	/// A filesystem operation could not establish the observation.
	System(io::Error),
}

impl std::fmt::Display for SyncPreviewError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::InvalidParent => formatter.write_str("invalid absolute sync parent path"),
			Self::AliasedRoots => {
				formatter.write_str("sync roots must identify distinct directories")
			}
			Self::AliasedFiles => formatter.write_str("sync names identify the same file"),
			Self::UnsupportedMount => {
				formatter.write_str("sync requires a whole local ext4, XFS or tmpfs mount")
			}
			Self::UnsupportedNamespace => {
				formatter.write_str("sync requires verified mount and user namespaces")
			}
			Self::UnsupportedHistoryNamePolicy => formatter
				.write_str("history preview requires exact unencrypted raw directory names"),
			#[cfg(feature = "experimental-linux-managed-sync")]
			Self::UnsupportedHistoryMountAttributes => {
				formatter.write_str("history preview requires verified native mount attributes")
			}
			#[cfg(feature = "experimental-linux-managed-sync")]
			Self::IdMappedHistoryMount => formatter.write_str("history preview refuses mount ID mapping"),
			Self::NameAlias => formatter.write_str("sync lookup found a differently spelled entry"),
			Self::DirectoryLimit => {
				formatter.write_str("sync directory scan exceeds its entry limit")
			}
			Self::Changed => formatter.write_str("selected sync scope changed during observation"),
			Self::Read(error) => error.fmt(formatter),
			Self::System(error) => error.fmt(formatter),
		}
	}
}

impl std::error::Error for SyncPreviewError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Read(error) => Some(error),
			Self::System(error) => Some(error),
			_ => None,
		}
	}
}

impl From<Errno> for SyncPreviewError {
	fn from(error: Errno) -> Self {
		Self::System(error.into())
	}
}

impl From<ReadError> for SyncPreviewError {
	fn from(error: ReadError) -> Self {
		match error {
			ReadError::IdentityChanged
			| ReadError::SourceChanged
			| ReadError::UnexpectedDataAfterEnd => Self::Changed,
			_ => Self::Read(error),
		}
	}
}

/// A read-only selection of two direct directory children of one held parent.
#[derive(Debug)]
pub struct SyncPreviewRoots<'selection> {
	parent_path: &'selection Path,
	parent: OwnedFd,
	parent_identity: FileIdentity,
	mount: u64,
	namespaces: namespaces::HeldNamespaces,
	names: [UnixComponent<'selection>; 2],
	roots: [ReadRoot; 2],
}

impl<'selection> SyncPreviewRoots<'selection> {
	/// Holds two distinct roots on one explicitly supported whole local mount.
	///
	/// # Errors
	/// Refuses invalid selections, aliases, symlinks, mount crossings and unavailable facts.
	pub fn open(
		parent_path: &'selection Path,
		names: [UnixComponent<'selection>; 2],
	) -> Result<Self, SyncPreviewError> {
		use SyncPreviewError as Error;

		let raw = parent_path.as_os_str().as_bytes();
		if raw.len() > MAX_PARENT_PATH_BYTES
			|| !parent_path.is_absolute()
			|| (raw != b"/"
				&& raw[1..]
					.split(|byte| *byte == b'/')
					.any(|part| UnixComponent::new(part).is_err()))
		{
			return Err(Error::InvalidParent);
		}
		if names[0] == names[1] {
			return Err(Error::AliasedRoots);
		}
		let namespaces = namespaces::HeldNamespaces::current()?;
		let parent = open_parent(parent_path)?;
		let parent_identity = FileIdentity::from_stat(&fs::fstat(&parent)?);
		let mount = local_mount(&parent)?;
		let [left, right] = names;
		let roots = [child_root(&parent, left)?, child_root(&parent, right)?];
		if roots[0].identity() == roots[1].identity() {
			return Err(Error::AliasedRoots);
		}
		namespaces.recheck_current()?;
		Ok(Self {
			parent_path,
			parent,
			parent_identity,
			mount,
			namespaces,
			names,
			roots,
		})
	}

	/// Returns ephemeral native identifiers for the held parent, ordered roots and mount.
	///
	/// Use these to describe this live report. They do not authorize a later lookup.
	#[must_use]
	pub fn selection(&self) -> SyncPreviewSelection {
		SyncPreviewSelection {
			parent: self.parent_identity,
			roots: self.roots.each_ref().map(ReadRoot::identity),
			mount_id: self.mount,
		}
	}

	/// Selects the same raw basename beneath both held roots.
	///
	/// # Errors
	/// Refuses unavailable, ambiguous or aliased selections.
	pub fn observe<'view>(
		&'view self,
		subject: UnixComponent<'view>,
	) -> Result<SyncPreviewPair<'view, 'selection>, SyncPreviewError> {
		self.recheck_scope()?;
		let entries = [
			probe(&self.roots[0], subject)?,
			probe(&self.roots[1], subject)?,
		];
		if let [Some(left), Some(right)] = entries.each_ref().map(HeldEntry::identity)
			&& left == right
		{
			return Err(SyncPreviewError::AliasedFiles);
		}
		Ok(SyncPreviewPair {
			roots: self,
			subject,
			entries,
		})
	}

	pub(in crate::linux) fn recheck_scope(&self) -> Result<(), SyncPreviewError> {
		self.namespaces.recheck_current()?;
		let current = open_parent(self.parent_path).map_err(rebound_error)?;
		let current_identity = FileIdentity::from_stat(&fs::fstat(&current)?);
		if current_identity != self.parent_identity
			|| mount_id(&self.parent)? != self.mount
			|| mount_id(&current)? != self.mount
		{
			return Err(SyncPreviewError::Changed);
		}
		for (root, name) in self.roots.iter().zip(self.names) {
			let rebound = child_root(&current, name).map_err(|error| match error {
				SyncPreviewError::System(error) => lookup_change(error),
				other => other,
			})?;
			if rebound.identity() != root.identity() || mount_id(rebound.directory())? != self.mount
			{
				return Err(SyncPreviewError::Changed);
			}
		}
		self.namespaces.recheck_current()
	}
}

/// Native identifiers held during a single live preview.
#[derive(Clone, Copy, Debug)]
pub struct SyncPreviewSelection {
	/// Held common parent identity.
	pub parent: FileIdentity,
	/// Held root identities, left followed by right.
	pub roots: [FileIdentity; 2],
	/// Mount identifier observed for the selected parent within the current namespace.
	pub mount_id: u64,
}

/// Both endpoint observations held for independent measurement and final recheck.
#[derive(Debug)]
pub struct SyncPreviewPair<'view, 'selection> {
	roots: &'view SyncPreviewRoots<'selection>,
	subject: UnixComponent<'view>,
	entries: [HeldEntry<'view>; 2],
}

/// Live observation of the exact selected name under one side.
#[derive(Clone, Copy, Debug)]
pub enum SyncPreviewEntry<'borrow, 'view> {
	/// A regular single-link file with ordinary permission bits.
	Present(&'borrow NamedReadView<'view>),
	/// An exact lookup reported absence on this held root.
	Absent,
	/// An entry exists outside the selected file profile.
	Unsupported,
}

impl<'view> SyncPreviewPair<'view, '_> {
	/// Borrows both observations in left-to-right order.
	#[must_use]
	pub fn entries(&self) -> [SyncPreviewEntry<'_, 'view>; 2] {
		self.entries.each_ref().map(|entry| match entry {
			HeldEntry::Present(view) => SyncPreviewEntry::Present(view),
			HeldEntry::Absent => SyncPreviewEntry::Absent,
			HeldEntry::Unsupported { .. } => SyncPreviewEntry::Unsupported,
		})
	}

	/// Revalidates the selected parent, roots and both names after measurement.
	///
	/// # Errors
	/// Refuses changed names, unavailable observations or files that changed after selection.
	pub fn recheck(&self) -> Result<(), SyncPreviewError> {
		use exacopy_endpoint::ReadView as _;

		self.roots.recheck_scope()?;
		for (root, entry) in self.roots.roots.iter().zip(&self.entries) {
			match entry {
				HeldEntry::Present(view) => {
					view.recheck_observation()?;
					names::confirm(root.directory(), self.subject, Some(view.identity()))?;
					view.recheck_observation()?;
				}
				HeldEntry::Absent if pin(root, self.subject)?.is_none() => {}
				HeldEntry::Unsupported { pin: held, stamp } => {
					let current = pin(root, self.subject)?.ok_or(SyncPreviewError::Changed)?;
					if entry_stamp(&fs::fstat(&current)?) != *stamp
						|| entry_stamp(&fs::fstat(held)?) != *stamp
					{
						return Err(SyncPreviewError::Changed);
					}
				}
				HeldEntry::Absent => return Err(SyncPreviewError::Changed),
			}
		}
		self.roots.recheck_scope()
	}
}

#[derive(Debug)]
enum HeldEntry<'view> {
	Present(NamedReadView<'view>),
	Absent,
	Unsupported { pin: OwnedFd, stamp: EntryStamp },
}

impl HeldEntry<'_> {
	fn identity(&self) -> Option<FileIdentity> {
		match self {
			Self::Present(view) => Some(view.identity()),
			Self::Unsupported { stamp, .. } => Some(stamp.identity),
			Self::Absent => None,
		}
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EntryStamp {
	identity: FileIdentity,
	mode: u32,
	uid: u32,
	gid: u32,
	link_count: u64,
}

#[cfg_attr(
	all(target_arch = "x86_64", target_pointer_width = "64"),
	expect(
		clippy::useless_conversion,
		reason = "Linux stat link counts vary by ABI"
	)
)]
fn entry_stamp(stat: &Stat) -> EntryStamp {
	EntryStamp {
		identity: FileIdentity::from_stat(stat),
		mode: stat.st_mode,
		uid: stat.st_uid,
		gid: stat.st_gid,
		link_count: stat.st_nlink.into(),
	}
}

fn open_parent(path: &Path) -> Result<OwnedFd, Errno> {
	fs::openat2(fs::CWD, path, DIRECTORY_FLAGS, Mode::empty(), NO_LINKS)
}

fn rebound_error(error: Errno) -> SyncPreviewError {
	lookup_change(error.into())
}

fn lookup_change(error: io::Error) -> SyncPreviewError {
	match Errno::from_io_error(&error) {
		Some(Errno::NOENT | Errno::LOOP | Errno::XDEV | Errno::NOTDIR) => SyncPreviewError::Changed,
		_ => SyncPreviewError::System(error),
	}
}

fn local_mount(parent: &OwnedFd) -> Result<u64, SyncPreviewError> {
	let table = MountObservations::capture().map_err(|_| SyncPreviewError::UnsupportedMount)?;
	let id = table
		.whole_filesystem_mount(parent)
		.map_err(|_| SyncPreviewError::UnsupportedMount)?;
	let record = table.record(id).ok_or(SyncPreviewError::UnsupportedMount)?;
	if !matches!(record.filesystem, b"ext4" | b"xfs" | b"tmpfs") {
		return Err(SyncPreviewError::UnsupportedMount);
	}
	Ok(id)
}

fn child_root(parent: &OwnedFd, name: UnixComponent<'_>) -> Result<ReadRoot, SyncPreviewError> {
	let directory = fs::openat2(
		parent,
		name.as_bytes(),
		DIRECTORY_FLAGS,
		Mode::empty(),
		CHILD_RESOLUTION,
	)?;
	let root = ReadRoot::from_directory(File::from(directory))?;
	names::confirm(parent, name, Some(root.identity()))?;
	Ok(root)
}

fn pin(root: &ReadRoot, name: UnixComponent<'_>) -> Result<Option<OwnedFd>, SyncPreviewError> {
	match fs::openat2(
		root.directory(),
		name.as_bytes(),
		OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
		Mode::empty(),
		CHILD_RESOLUTION,
	) {
		Ok(file) => {
			let identity = FileIdentity::from_stat(&fs::fstat(&file)?);
			names::confirm(root.directory(), name, Some(identity))?;
			Ok(Some(file))
		}
		Err(Errno::NOENT) => {
			names::confirm(root.directory(), name, None)?;
			Ok(None)
		}
		Err(error) => Err(error.into()),
	}
}

fn probe<'view>(
	root: &'view ReadRoot,
	name: UnixComponent<'view>,
) -> Result<HeldEntry<'view>, SyncPreviewError> {
	let Some(pinned) = pin(root, name)? else {
		return Ok(HeldEntry::Absent);
	};
	let stat = fs::fstat(&pinned)?;
	if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
		|| Mode::from_raw_mode(stat.st_mode).as_raw_mode() > ORDINARY_PERMISSION_BITS
		|| stat.st_nlink != 1
	{
		return Ok(HeldEntry::Unsupported {
			pin: pinned,
			stamp: entry_stamp(&stat),
		});
	}
	let view = NamedReadView::open(root, name)?;
	let metadata = view.metadata();
	if view.identity() != FileIdentity::from_stat(&stat)
		|| metadata.link_count() != 1
		|| metadata.mode() > ORDINARY_PERMISSION_BITS
	{
		return Err(SyncPreviewError::Changed);
	}
	Ok(HeldEntry::Present(view))
}
