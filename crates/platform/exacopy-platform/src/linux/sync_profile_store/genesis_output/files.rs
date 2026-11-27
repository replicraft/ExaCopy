use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::fs::FileExt as _;

use exacopy_endpoint::write_all_at;

use rustix::fs::{self, Mode, OFlags, RawDir};

use super::super::pin::{Pin, Stamp};
use super::super::{
	BELOW, DIRECTORY, DirectoryStamp, LEAF, PRIVATE_DIRECTORY, PRIVATE_FILE, SyncProfileStoreError,
	mount_id, open_child,
};
use super::{FileIdentity, SyncGenesisEffect, SyncGenesisMember};

pub(super) const MEMBER_LIMIT: usize = 2_048;
pub(super) const MEMBER_NAMES: [&[u8]; 4] =
	[b"root.cbor", b"left.cbor", b"right.cbor", b"leaf.cbor"];

pub(super) fn create_record<G>(
	parent: &File,
	name: &[u8],
	bytes: &[u8],
	owner: u32,
	mount: u64,
	member: Option<SyncGenesisMember>,
	enter: &mut impl FnMut(SyncGenesisEffect) -> Result<G, SyncProfileStoreError>,
) -> Result<Pin, SyncProfileStoreError> {
	let writer = {
		let _authority = enter(member.map_or(
			SyncGenesisEffect::CreateIntent,
			SyncGenesisEffect::CreateMember,
		))?;
		File::from(fs::openat2(
			parent,
			name,
			LEAF | OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
			PRIVATE_FILE,
			BELOW,
		)?)
	};
	let empty = Stamp::observe(&writer, owner, mount)?;
	if empty.extent != 0 {
		return Err(SyncProfileStoreError::Changed);
	}
	empty.require_name(parent, name)?;
	{
		let _authority = enter(member.map_or(
			SyncGenesisEffect::WriteIntent,
			SyncGenesisEffect::WriteMember,
		))?;
		if Stamp::observe(&writer, owner, mount)? != empty {
			return Err(SyncProfileStoreError::Changed);
		}
		empty.require_name(parent, name)?;
		write_all_at(0, bytes, |offset, chunk| writer.write_at(chunk, offset))
			.map_err(io::Error::other)?;
	}
	let written = Stamp::observe(&writer, owner, mount)?;
	if written.identity != empty.identity || written.extent != bytes.len() {
		return Err(SyncProfileStoreError::Changed);
	}
	{
		let _authority =
			enter(member.map_or(SyncGenesisEffect::SyncIntent, SyncGenesisEffect::SyncMember))?;
		if Stamp::observe(&writer, owner, mount)? != written {
			return Err(SyncProfileStoreError::Changed);
		}
		written.require_name(parent, name)?;
		writer.sync_all()?;
	}
	written.require_name(parent, name)?;
	drop(writer);

	let pin = Pin::open(parent, name, owner, mount)?;
	if pin.stamp != written {
		return Err(SyncProfileStoreError::Changed);
	}
	recheck_record(parent, &pin, bytes)?;
	Ok(pin)
}

pub(super) fn recheck_record(
	parent: &File,
	pin: &Pin,
	bytes: &[u8],
) -> Result<(), SyncProfileStoreError> {
	let mut readback = [0; MEMBER_LIMIT];
	let extent = readback
		.get_mut(..bytes.len())
		.ok_or(SyncProfileStoreError::InvalidExtent)?;
	pin.read(parent, extent, &mut [0])?;
	if extent != bytes {
		return Err(SyncProfileStoreError::Changed);
	}
	Ok(())
}

pub(super) struct StageDirectory {
	pub(super) file: File,
	pub(super) identity: FileIdentity,
}

impl StageDirectory {
	pub(super) fn open(
		parent: &File,
		name: &[u8],
		owner: u32,
		mount: u64,
	) -> Result<Self, SyncProfileStoreError> {
		let file = open_child(parent, name)?;
		let identity = DirectoryStamp::observe(&file, owner)?.identity;
		require_directory(parent, name, &file, identity, owner, mount)?;
		Ok(Self { file, identity })
	}

	pub(super) fn populate<G>(
		self,
		parent: &File,
		stage_name: &[u8],
		members: [&[u8]; 4],
		owner: u32,
		mount: u64,
		enter: &mut impl FnMut(SyncGenesisEffect) -> Result<G, SyncProfileStoreError>,
	) -> Result<Stage, SyncProfileStoreError> {
		require_directory(parent, stage_name, &self.file, self.identity, owner, mount)?;
		check_empty(&self.file)?;
		let mut stage_effect = |effect| {
			let guard = enter(effect)?;
			require_directory(parent, stage_name, &self.file, self.identity, owner, mount)?;
			Ok(guard)
		};
		let create = |member: SyncGenesisMember, enter: &mut _| {
			let index = member as usize;
			create_record(
				&self.file,
				MEMBER_NAMES[index],
				members[index],
				owner,
				mount,
				Some(member),
				enter,
			)
		};
		let pins = [
			create(SyncGenesisMember::Root, &mut stage_effect)?,
			create(SyncGenesisMember::Left, &mut stage_effect)?,
			create(SyncGenesisMember::Right, &mut stage_effect)?,
			create(SyncGenesisMember::Leaf, &mut stage_effect)?,
		];
		let stage = Stage {
			directory: self.file,
			identity: self.identity,
			pins,
		};
		stage.recheck(parent, stage_name, members, owner, mount)?;
		Ok(stage)
	}
}

pub(super) struct Stage {
	pub(super) directory: File,
	pub(super) identity: FileIdentity,
	pins: [Pin; 4],
}

impl Stage {
	pub(super) fn verify(
		&self,
		members: [&[u8]; 4],
		verify: impl FnOnce([&[u8]; 4]) -> std::io::Result<()>,
	) -> Result<(), SyncProfileStoreError> {
		let mut readback = [[0; MEMBER_LIMIT]; 4];
		for ((pin, expected), buffer) in self.pins.iter().zip(members).zip(&mut readback) {
			let extent = buffer
				.get_mut(..expected.len())
				.ok_or(SyncProfileStoreError::InvalidExtent)?;
			pin.read(&self.directory, extent, &mut [0])?;
			if extent != expected {
				return Err(SyncProfileStoreError::Changed);
			}
		}
		let measured = std::array::from_fn(|index| &readback[index][..members[index].len()]);
		verify(measured)?;
		Ok(())
	}

	pub(super) fn recheck(
		&self,
		parent: &File,
		name: &[u8],
		members: [&[u8]; 4],
		owner: u32,
		mount: u64,
	) -> Result<(), SyncProfileStoreError> {
		require_directory(parent, name, &self.directory, self.identity, owner, mount)?;
		let identities = self.pins.each_ref().map(|pin| pin.stamp.identity);
		check_inventory(&self.directory, identities, OFlags::empty())?;
		for (pin, bytes) in self.pins.iter().zip(members) {
			recheck_record(&self.directory, pin, bytes)?;
		}
		check_inventory(&self.directory, identities, OFlags::empty())?;
		require_directory(parent, name, &self.directory, self.identity, owner, mount)
	}
}

pub(super) fn require_directory(
	parent: &File,
	name: &[u8],
	directory: &File,
	identity: FileIdentity,
	owner: u32,
	mount: u64,
) -> Result<(), SyncProfileStoreError> {
	let named = open_child(parent, name)?;
	for directory in [directory, &named] {
		let observed = DirectoryStamp::observe(directory, owner)?;
		if observed.identity != identity
			|| observed.owner != owner
			|| observed.mode != PRIVATE_DIRECTORY
			|| mount_id(directory)? != mount
		{
			return Err(SyncProfileStoreError::Changed);
		}
	}
	Ok(())
}

fn check_empty(directory: &File) -> Result<(), SyncProfileStoreError> {
	let fresh = readdir_file(directory, OFlags::empty())?;
	let mut scratch = [MaybeUninit::uninit(); 1024];
	let mut entries = RawDir::new(fresh, &mut scratch);
	for _ in 0..2 {
		let Some(entry) = entries.next() else {
			return Err(SyncProfileStoreError::Changed);
		};
		if !matches!(entry?.file_name().to_bytes(), b"." | b"..") {
			return Err(SyncProfileStoreError::Changed);
		}
	}
	if entries.next().is_some() {
		return Err(SyncProfileStoreError::Changed);
	}
	Ok(())
}

fn readdir_file(directory: &File, flags: OFlags) -> Result<File, SyncProfileStoreError> {
	Ok(fs::openat2(
		directory,
		c".",
		DIRECTORY | OFlags::RDONLY | OFlags::NOFOLLOW | flags,
		Mode::empty(),
		BELOW,
	)?
	.into())
}

pub(super) fn check_inventory(
	directory: &File,
	identities: [FileIdentity; 4],
	flags: OFlags,
) -> Result<(), SyncProfileStoreError> {
	let fresh = readdir_file(directory, flags)?;
	let mut scratch = [MaybeUninit::uninit(); 1024];
	let mut entries = RawDir::new(fresh, &mut scratch);
	let mut found = [false; 4];
	for _ in 0..6 {
		let Some(entry) = entries.next() else {
			return Err(SyncProfileStoreError::Changed);
		};
		let entry = entry?;
		let name = entry.file_name().to_bytes();
		if matches!(name, b"." | b"..") {
			continue;
		}
		let index = MEMBER_NAMES
			.iter()
			.position(|expected| *expected == name)
			.ok_or(SyncProfileStoreError::Changed)?;
		if found[index] || entry.ino() != identities[index].inode() {
			return Err(SyncProfileStoreError::Changed);
		}
		found[index] = true;
	}
	if found.into_iter().all(|found| found) && entries.next().is_none() {
		return Ok(());
	}
	Err(SyncProfileStoreError::Changed)
}
