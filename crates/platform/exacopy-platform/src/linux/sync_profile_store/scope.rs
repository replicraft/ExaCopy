use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;

use rustix::fs::{self, FileType, Mode, OFlags};

use super::{
	DIRECTORY, FileIdentity, MountObservations, SyncProfileStore, SyncProfileStoreError,
	SyncProfileStoreRecord,
};
use crate::linux::{ReadRoot, SyncPreviewRoots};

const MAX_ANCESTORS: usize = 256;

const NONEXACT_NAME_FLAGS: u32 = 0x4000_0000 | 0x0000_0800; // Ext4 casefold and encryption.
const OTHER_WRITE: Mode = Mode::WGRP.union(Mode::WOTH);

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct DirectoryStamp {
	pub(super) identity: FileIdentity,
	pub(super) owner: u32,
	group: u32,
	pub(super) mode: Mode,
}

impl DirectoryStamp {
	pub(super) fn observe(file: impl AsFd, owner: u32) -> Result<Self, SyncProfileStoreError> {
		let fd = file.as_fd();
		let observed = fs::fstat(fd)?;
		let mode = Mode::from_raw_mode(observed.st_mode);
		if FileType::from_raw_mode(observed.st_mode) != FileType::Directory
			|| (observed.st_uid != owner && observed.st_uid != 0)
			|| mode.intersects(OTHER_WRITE)
			|| observed.st_nlink == 0
			|| fs::ioctl_getflags(fd)?.bits() & NONEXACT_NAME_FLAGS != 0
		{
			return Err(SyncProfileStoreError::Unprotected);
		}
		Ok(Self {
			identity: FileIdentity::from_stat(&observed),
			owner: observed.st_uid,
			group: observed.st_gid,
			mode,
		})
	}
}

/// Held read-only history directory selected independently from the profile.
pub struct SyncProfileHistory {
	custody: SyncProfileStore,
	root: ReadRoot,
}

impl SyncProfileHistory {
	/// Borrow the exact held read root for explicitly selected history members.
	#[must_use]
	pub const fn read_root(&self) -> &ReadRoot {
		&self.root
	}

	/// Recheck the exact protected history path and its original held inode.
	///
	/// # Errors
	/// Refuses changed root identity, protected ancestry or mount.
	pub fn recheck(&self) -> Result<(), SyncProfileStoreError> {
		self.custody.recheck()?;
		if directory_identity(self.root.directory())? != self.custody.identity() {
			return Err(SyncProfileStoreError::Changed);
		}
		Ok(())
	}
}

impl SyncProfileStoreRecord<'_> {
	/// Opens selected history through the store borrowed by this original record.
	///
	/// # Errors
	/// Refuses unprotected, aliased or unavailable history paths.
	pub fn open_history(&self, path: &Path) -> Result<SyncProfileHistory, SyncProfileStoreError> {
		self.store.open_history(path)
	}

	/// Rechecks the original record and its profile/history/live-root separation.
	///
	/// Uses the record's original store without acquiring another profile lease.
	///
	/// # Errors
	/// Refuses changed record custody, overlapping roles or unsupported ancestry.
	pub fn recheck_history_scope(
		&self,
		history: &SyncProfileHistory,
		roots: &SyncPreviewRoots<'_>,
	) -> Result<(), SyncProfileStoreError> {
		self.recheck()?;
		self.store.check_disjoint(history, roots)
	}
}

impl SyncProfileStore {
	/// Opens one independently selected existing private history directory.
	///
	/// # Errors
	/// Refuses unprotected, aliased or unavailable history paths.
	pub fn open_history(&self, path: &Path) -> Result<SyncProfileHistory, SyncProfileStoreError> {
		let custody = Self::open(path)?;
		let root = ReadRoot::from_directory(custody.profile().file.try_clone()?)
			.map_err(io::Error::other)?;
		let history = SyncProfileHistory { custody, root };
		history.recheck()?;
		Ok(history)
	}

	/// Check physical disjointness of the profile, history and both live child roots.
	///
	/// Common ancestors are allowed. Device/inode comparison also catches
	/// spelling or whole-mount aliases to a selected scope.
	///
	/// # Errors
	/// Refuses any overlap, changed observations or unsupported ancestry.
	pub fn check_disjoint(
		&self,
		history: &SyncProfileHistory,
		roots: &SyncPreviewRoots<'_>,
	) -> Result<(), SyncProfileStoreError> {
		let first = self.role_ancestries(history, roots)?;
		require_disjoint(first.each_ref().map(Vec::as_slice))?;
		if self.role_ancestries(history, roots)? != first {
			return Err(SyncProfileStoreError::Changed);
		}
		Ok(())
	}

	// The live common parent intentionally contains the selected children;
	// profile and output must each be disjoint from all of those held roles.
	pub(super) fn check_genesis_output_disjoint(
		&self,
		output: &Self,
		roots: &SyncPreviewRoots<'_>,
	) -> Result<(), SyncProfileStoreError> {
		let observe = || {
			self.recheck()?;
			output.recheck()?;
			roots.recheck_scope().map_err(io::Error::other)?;
			let mounts = MountObservations::capture()?;
			let system_root = self.chain.first().ok_or(SyncProfileStoreError::Changed)?;
			let walk = |root| ancestry(root, &mounts, system_root.stamp.identity);
			let [parent, left, right] = roots.held_directories();
			let chains = [
				walk(self.profile().file.as_fd())?,
				walk(output.profile().file.as_fd())?,
				walk(parent)?,
				walk(left)?,
				walk(right)?,
			];
			roots.recheck_scope().map_err(io::Error::other)?;
			output.recheck()?;
			self.recheck()?;
			Ok::<_, SyncProfileStoreError>(chains)
		};
		let first = observe()?;
		for role in &first[2..] {
			require_disjoint([first[0].as_slice(), first[1].as_slice(), role.as_slice()])?;
		}
		if observe()? != first {
			return Err(SyncProfileStoreError::Changed);
		}
		Ok(())
	}

	fn role_ancestries(
		&self,
		history: &SyncProfileHistory,
		roots: &SyncPreviewRoots<'_>,
	) -> Result<[Vec<FileIdentity>; 4], SyncProfileStoreError> {
		self.recheck()?;
		history.recheck()?;
		roots.recheck_scope().map_err(io::Error::other)?;
		let mounts = MountObservations::capture()?;
		let system_root = self.chain.first().ok_or(SyncProfileStoreError::Changed)?;
		let [_, left, right] = roots.held_directories();
		let walk = |root| ancestry(root, &mounts, system_root.stamp.identity);
		let profile = walk(self.profile().file.as_fd())?;
		let historical = walk(history.root.directory().as_fd())?;
		let left = walk(left)?;
		let right = walk(right)?;
		roots.recheck_scope().map_err(io::Error::other)?;
		history.recheck()?;
		self.recheck()?;
		Ok([profile, historical, left, right])
	}
}

fn directory_identity(file: &File) -> Result<FileIdentity, SyncProfileStoreError> {
	let observed = fs::fstat(file)?;
	if FileType::from_raw_mode(observed.st_mode) != FileType::Directory || observed.st_nlink == 0 {
		return Err(SyncProfileStoreError::Changed);
	}
	Ok(FileIdentity::from_stat(&observed))
}

fn ancestry(
	start: BorrowedFd<'_>,
	mounts: &MountObservations,
	system_root: FileIdentity,
) -> Result<Vec<FileIdentity>, SyncProfileStoreError> {
	let mut directory = File::from(start.try_clone_to_owned()?);
	let mut chain = Vec::new();
	for _ in 0..MAX_ANCESTORS {
		mounts.whole_filesystem_mount(&directory)?;
		let identity = directory_identity(&directory)?;
		if chain.contains(&identity) {
			return Err(SyncProfileStoreError::Changed);
		}
		chain.push(identity);
		if identity == system_root {
			return Ok(chain);
		}
		// A fixed native parent walk permits ordinary ancestors above a whole mount.
		directory = fs::openat(
			&directory,
			c"..",
			DIRECTORY | OFlags::PATH | OFlags::NOFOLLOW,
			Mode::empty(),
		)?
		.into();
	}
	Err(SyncProfileStoreError::Unsupported)
}

fn require_disjoint<const N: usize>(
	chains: [&[FileIdentity]; N],
) -> Result<(), SyncProfileStoreError> {
	for (index, left) in chains.iter().enumerate() {
		let left_root = left.first().ok_or(SyncProfileStoreError::Changed)?;
		for right in &chains[index + 1..] {
			let right_root = right.first().ok_or(SyncProfileStoreError::Changed)?;
			if left.contains(right_root) || right.contains(left_root) {
				return Err(SyncProfileStoreError::OverlappingRoles);
			}
		}
	}
	Ok(())
}
