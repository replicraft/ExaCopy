//! Original read-only action slot under the managed preparation lease.

use std::fmt;
use std::fs::File;
use std::io;
use std::num::{NonZeroU64, NonZeroUsize};

use exacopy_endpoint::{MAX_FILE_LENGTH, UnixComponent};
use rustix::fs::{self, FlockOperation};
use rustix::io::Errno;

use crate::linux::job::FIRST_SEGMENT;
use crate::linux::sync_preview::{ManagedSyncPreparationLease, unique_mount_id};
use crate::linux::{ManagedSyncError, ManagedSyncExpectedObject, SyncPreviewError};

use super::pin::{Pin, SelectedPin};
use super::{
	DirectoryStamp, PRIVATE_DIRECTORY, SyncProfileHistory, SyncProfileStoreError,
	SyncProfileStoreRecord, mount_id, open_child,
};

mod preparation;
mod role_bytes;
#[cfg(test)]
mod tests;

use PreparedManagedActionError as Error;
pub use preparation::{PreparedActionRoleFacts, PreparedManagedActionView};
pub use role_bytes::PreparedActionRoleBytes;

/// Native expectations supplied by an independently authenticated action selection.
#[derive(Clone, Copy)]
pub struct PreparedActionSlotSelection<'name> {
	/// Exact direct-child name in the held profile.
	pub name: UnixComponent<'name>,
	/// Original private action directory device and inode.
	pub directory: ManagedSyncExpectedObject,
	/// Original fixed first-segment device and inode.
	pub segment: ManagedSyncExpectedObject,
	/// Independently selected ordinary mount of the profile storage.
	pub ordinary_mount: NonZeroU64,
	/// Independently selected unique mount of the profile storage.
	pub unique_mount: NonZeroU64,
	/// Exact selected nonzero physical prepared extent.
	pub extent: NonZeroUsize,
	/// Independently selected prepared-record byte limit.
	pub limit: NonZeroUsize,
}

/// Refusal of the protected, read-only managed action preparation.
#[derive(Debug)]
#[non_exhaustive]
pub enum PreparedManagedActionError {
	/// The selected extent or caller buffer exceeded the admitted bounds.
	Bounds,
	/// Original protected policy recheck or history open refused.
	Policy(SyncProfileStoreError),
	/// The exact original live root pair could not be opened.
	Roots(SyncPreviewError),
	/// The exclusive managed pair or later subject observation refused.
	Pair(ManagedSyncError),
	/// Original physical role separation or joined native facts refused.
	Scope(SyncProfileStoreError),
	/// The original private action directory or its lease refused.
	Directory(SyncProfileStoreError),
	/// The original fixed prepared segment or its exact readback refused.
	Segment(SyncProfileStoreError),
}

impl fmt::Display for Error {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Bounds => formatter.write_str("managed action prepared extent refused"),
			Self::Policy(cause) => write!(formatter, "managed action policy custody: {cause}"),
			Self::Roots(cause) => write!(formatter, "managed action root custody: {cause}"),
			Self::Pair(cause) => write!(formatter, "managed action pair custody: {cause}"),
			Self::Scope(cause) => write!(formatter, "managed action role separation: {cause}"),
			Self::Directory(cause) => write!(formatter, "managed action slot custody: {cause}"),
			Self::Segment(cause) => write!(formatter, "managed action segment custody: {cause}"),
		}
	}
}

impl std::error::Error for Error {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Bounds => None,
			Self::Roots(cause) => Some(cause),
			Self::Pair(cause) => Some(cause),
			Self::Policy(cause)
			| Self::Scope(cause)
			| Self::Directory(cause)
			| Self::Segment(cause) => Some(cause),
		}
	}
}

/// Keeps the original profile shared lock, pair exclusive lock and its own slot exclusive lock.
/// Its fixed segment is read-only. Accepted prepared history is an application observation.
pub(super) struct HeldActionSlot<'view, 'store, 'held, 'selection> {
	record: &'view SyncProfileStoreRecord<'store>,
	history: &'view SyncProfileHistory,
	pair: &'view ManagedSyncPreparationLease<'held, 'selection>,
	selection: PreparedActionSlotSelection<'view>,
	directory: File,
	stamp: DirectoryStamp,
	segment: Pin,
}

impl<'store> SyncProfileStoreRecord<'store> {
	pub(super) fn open_selected_action_slot<'view, 'held, 'selection>(
		&'view self,
		history: &'view SyncProfileHistory,
		pair: &'view ManagedSyncPreparationLease<'held, 'selection>,
		selection: PreparedActionSlotSelection<'view>,
	) -> Result<HeldActionSlot<'view, 'store, 'held, 'selection>, Error> {
		if selection.extent > selection.limit
			|| !u64::try_from(selection.limit.get()).is_ok_and(|limit| limit <= MAX_FILE_LENGTH)
		{
			return Err(Error::Bounds);
		}
		self.recheck().map_err(Error::Policy)?;
		pair.recheck_roots().map_err(Error::Pair)?;
		let name = selection.name.as_bytes();
		let directory = open_child(&self.lease, name).map_err(Error::Directory)?;
		let stamp =
			observe_directory(&directory, self.store.owner, selection).map_err(Error::Directory)?;
		self.store
			.check_action_slot_scope(history, pair.held_roots(), &directory)
			.map_err(Error::Scope)?;
		fs::flock(&directory, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
			Error::Directory(if error == Errno::WOULDBLOCK {
				SyncProfileStoreError::Busy
			} else {
				error.into()
			})
		})?;
		check_scope(self, history, pair, selection, &directory, stamp)?;
		let segment = Pin::open_selected(
			&directory,
			FIRST_SEGMENT.as_bytes(),
			self.store.owner,
			selection.ordinary_mount.get(),
			SelectedPin {
				identity: selection.segment,
				extent: selection.extent.get(),
				unique_mount: selection.unique_mount,
			},
		)
		.map_err(Error::Segment)?;
		let slot = HeldActionSlot {
			record: self,
			history,
			pair,
			selection,
			directory,
			stamp,
			segment,
		};
		slot.recheck()?;
		Ok(slot)
	}
}

impl HeldActionSlot<'_, '_, '_, '_> {
	// The caller supplies the byte buffer. The read neither authenticates
	// prepared history nor authorizes another operation.
	pub(super) fn read_prepared(&self, output: &mut [u8]) -> Result<(), Error> {
		if output.len() != self.selection.extent.get() {
			return Err(Error::Bounds);
		}
		self.recheck()?;
		self.segment
			.read_selected(&self.directory, self.selection.unique_mount, output)
			.map_err(Error::Segment)?;
		self.recheck()
	}

	fn recheck(&self) -> Result<(), Error> {
		check_scope(
			self.record,
			self.history,
			self.pair,
			self.selection,
			&self.directory,
			self.stamp,
		)?;
		self.segment
			.check_selected(&self.directory, self.selection.unique_mount)
			.map_err(Error::Segment)
	}
}

fn check_scope(
	record: &SyncProfileStoreRecord<'_>,
	history: &SyncProfileHistory,
	pair: &ManagedSyncPreparationLease<'_, '_>,
	selection: PreparedActionSlotSelection<'_>,
	directory: &File,
	stamp: DirectoryStamp,
) -> Result<(), Error> {
	record.recheck().map_err(Error::Policy)?;
	pair.recheck_roots().map_err(Error::Pair)?;
	record
		.store
		.check_action_slot_scope(history, pair.held_roots(), directory)
		.map_err(Error::Scope)?;
	let named = open_child(&record.lease, selection.name.as_bytes()).map_err(Error::Directory)?;
	for candidate in [directory, &named] {
		if observe_directory(candidate, record.store.owner, selection).map_err(Error::Directory)?
			!= stamp
		{
			return Err(Error::Directory(SyncProfileStoreError::Changed));
		}
	}
	pair.recheck_roots().map_err(Error::Pair)?;
	record.recheck().map_err(Error::Policy)
}

fn observe_directory(
	file: &File,
	owner: u32,
	selection: PreparedActionSlotSelection<'_>,
) -> Result<DirectoryStamp, SyncProfileStoreError> {
	let stamp = DirectoryStamp::observe(file, owner)?;
	if stamp.owner != owner || stamp.mode != PRIVATE_DIRECTORY {
		return Err(SyncProfileStoreError::Unprotected);
	}
	if !selection.directory.matches(stamp.identity)
		|| mount_id(file)? != selection.ordinary_mount.get()
		|| unique_mount_id(file).map_err(io::Error::other)? != selection.unique_mount
	{
		return Err(SyncProfileStoreError::Changed);
	}
	Ok(stamp)
}
