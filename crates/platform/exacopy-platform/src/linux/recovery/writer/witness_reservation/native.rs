use std::fs::File;

use exacopy_endpoint::linux_job::JobFileIdentity;
use rustix::fs::{self, FallocateFlags, Mode, OFlags};
use rustix::process::{getegid, geteuid};

use crate::linux::source::check_logical_eof;
use crate::linux::stage::{CHILD_RESOLVE, FILE_MODE};
use crate::linux::{FileIdentity, SourceObservation, StageError};

use super::{HeldReservation, mount_id};

// The protocol reserves the entire admitted sealed-receipt envelope.
pub(super) const RECEIPT_CAPACITY: u64 = 6_144;

pub(super) struct AnonymousReceipt {
	file: File,
	pub(super) observation: SourceObservation,
}

impl AnonymousReceipt {
	pub(super) fn file(&self) -> &File {
		&self.file
	}

	pub(super) fn close_writer(&mut self, independently_opened: File) {
		self.file = independently_opened;
	}

	pub(super) fn observe(
		file: File,
		held: &HeldReservation<'_>,
		segment: FileIdentity,
	) -> Result<Self, StageError> {
		let observation = inspect_anonymous(&file, held.lease.job().root.mount)?;
		let stage = held.stage.selection();
		let conflicts: [JobFileIdentity; 5] = [
			held.lease.job().destination_identity().into(),
			held.lease.job().identity().into(),
			stage.directory,
			stage.file,
			segment.into(),
		];
		if conflicts.contains(&observation.identity().into()) {
			return Err(StageError::IdentityChanged);
		}
		Ok(Self { file, observation })
	}

	pub(super) fn recheck(&self, held: &HeldReservation<'_>) -> Result<(), StageError> {
		let current = inspect_anonymous(&self.file, held.lease.job().root.mount)?;
		self.observation
			.recheck(current)
			.map_err(StageError::ReadBack)
	}

	pub(super) fn allocate(&self) -> rustix::io::Result<()> {
		allocate(&self.file, 0, RECEIPT_CAPACITY)
	}

	pub(super) fn after_allocation(
		self,
		held: &HeldReservation<'_>,
		segment: FileIdentity,
	) -> Result<Self, StageError> {
		let before = self.observation;
		let updated = Self::observe(self.file, held, segment)?;
		check_after_allocation(before, updated.observation)?;
		Ok(updated)
	}
}

pub(super) fn open_anonymous(directory: &File) -> rustix::io::Result<std::os::fd::OwnedFd> {
	// O_EXCL on O_TMPFILE would prevent the separately qualified later link.
	fs::openat2(
		directory,
		c".",
		OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOATIME,
		Mode::from_raw_mode(FILE_MODE.as_raw_mode()),
		CHILD_RESOLVE,
	)
}

pub(super) fn allocate(file: &File, offset: u64, length: u64) -> rustix::io::Result<()> {
	fs::fallocate(file, FallocateFlags::KEEP_SIZE, offset, length)
}

pub(super) fn inspect_anonymous(file: &File, mount: u64) -> Result<SourceObservation, StageError> {
	let stat = fs::fstat(file)?;
	let observation = SourceObservation::capture(&stat).map_err(StageError::ReadBack)?;
	if observation.mode() != FILE_MODE.as_raw_mode()
		|| observation.owner() != geteuid().as_raw()
		|| observation.group() != getegid().as_raw()
		|| observation.link_count() != 0
		|| !observation.is_empty()
	{
		return Err(StageError::UnsafeFile);
	}
	if mount_id(file)? != mount {
		return Err(StageError::IdentityChanged);
	}
	check_logical_eof(file, 0).map_err(StageError::ReadBack)?;
	Ok(observation)
}

pub(super) fn check_after_allocation(
	before: SourceObservation,
	after: SourceObservation,
) -> Result<(), StageError> {
	// KEEP_SIZE may refresh both mtime and ctime through file_modified, even
	// without extending EOF. Accept that transition only across our own held
	// allocation; the caller still compares every old journal byte and adopts
	// a complete new observation for subsequent rechecks.
	if before.identity() != after.identity()
		|| before.len() != after.len()
		|| before.mode() != after.mode()
		|| before.owner() != after.owner()
		|| before.group() != after.group()
		|| before.link_count() != after.link_count()
		|| before.accessed_at() != after.accessed_at()
	{
		return Err(StageError::IdentityChanged);
	}
	Ok(())
}
