//! One explicitly selected immutable managed-sync record in an existing local profile.

use std::fmt;
use std::fs::File;
use std::io::{self, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use rustix::fs::{self, FlockOperation, FsWord, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;
use rustix::process::{geteuid, getuid};

use super::handle::mount_id;
use super::owner_seed::{KEY_NAME, OWNER_SEED_BYTES};
use super::{FileIdentity, MountObservations};
use crate::protected_snapshot::checked_components;

mod pin;
mod scope;
#[cfg(test)]
mod tests;

use pin::{Pin, Stamp};
use scope::DirectoryStamp;
pub use scope::SyncProfileHistory;

const EXT4_SUPER_MAGIC: FsWord = 0xef53; // Linux <uapi/linux/magic.h>.
const MAX_RECORD_BYTES: usize = 24 * 1024;
const DIRECTORY: OFlags = OFlags::DIRECTORY.union(OFlags::CLOEXEC);
const LEAF: OFlags = OFlags::CLOEXEC
	.union(OFlags::NOFOLLOW)
	.union(OFlags::NONBLOCK);
const NO_LINKS: ResolveFlags = ResolveFlags::NO_SYMLINKS.union(ResolveFlags::NO_MAGICLINKS);
const BELOW: ResolveFlags = NO_LINKS
	.union(ResolveFlags::BENEATH)
	.union(ResolveFlags::NO_XDEV);
const PRIVATE_DIRECTORY: Mode = Mode::RUSR.union(Mode::WUSR).union(Mode::XUSR);
const PRIVATE_FILE: Mode = Mode::RUSR.union(Mode::WUSR);

/// Failure to establish custody of an exact managed-sync profile record.
#[derive(Debug)]
#[non_exhaustive]
pub enum SyncProfileStoreError {
	/// The independently selected profile, history or live roots overlap.
	OverlappingRoles,
	/// Invalid profile path or zero selection ID.
	InvalidSelection,
	/// The effective actor, protected ancestry, or native mount is unsupported.
	Unsupported,
	/// A directory or regular file lacks required private metadata.
	Unprotected,
	/// Exact held or named custody or content changed.
	Changed,
	/// A record is empty or exceeds the private store's bound.
	InvalidExtent,
	/// A cooperating reader or writer holds an incompatible profile lease.
	Busy,
	/// The fixed selection slot is already occupied.
	AlreadyExists,
	/// A native prerequisite could not be checked.
	System(io::Error),
	/// Error after exclusive creation. Retain the slot for owner reconciliation.
	CreationUnconfirmed(Box<Self>),
}

impl fmt::Display for SyncProfileStoreError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::OverlappingRoles => {
				formatter.write_str("managed-sync profile, history and live roots overlap")
			}
			Self::InvalidSelection => formatter.write_str("invalid managed-sync store selection"),
			Self::Unsupported => formatter.write_str("unsupported managed-sync store substrate"),
			Self::Unprotected => formatter.write_str("managed-sync store metadata is not private"),
			Self::Changed => formatter.write_str("managed-sync store observation changed"),
			Self::InvalidExtent => formatter.write_str("invalid managed-sync record extent"),
			Self::Busy => formatter.write_str("managed-sync profile is held by another operation"),
			Self::AlreadyExists => formatter.write_str("managed-sync selection slot is occupied"),
			Self::System(error) => error.fmt(formatter),
			Self::CreationUnconfirmed(error) => {
				write!(formatter, "managed-sync creation unconfirmed: {error}")
			}
		}
	}
}

impl std::error::Error for SyncProfileStoreError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::System(error) => Some(error),
			Self::CreationUnconfirmed(error) => Some(error.as_ref()),
			_ => None,
		}
	}
}

impl From<io::Error> for SyncProfileStoreError {
	fn from(error: io::Error) -> Self {
		Self::System(error)
	}
}

impl From<Errno> for SyncProfileStoreError {
	fn from(error: Errno) -> Self {
		Self::System(error.into())
	}
}

/// Seed-free held location of an independently selected existing private profile.
///
/// The application supplies authority. The protected filesystem and cooperative
/// profile-lock scope exclude uncontrolled same-owner writers and hold no
/// authority over live sync roots or history.
pub struct SyncProfileStore {
	chain: Vec<HeldComponent>,
	owner: u32,
	mount: u64,
}

struct HeldComponent {
	name: Vec<u8>,
	file: File,
	stamp: DirectoryStamp,
}

impl SyncProfileStore {
	/// Pins an absolute raw path to the current owner's existing mode-0700 profile.
	///
	/// # Errors
	/// Refuses noncanonical components, root or changed credentials, unprotected
	/// ancestors, symlinks, mounts across the profile path and unsupported native observations.
	pub fn open(profile: &Path) -> Result<Self, SyncProfileStoreError> {
		let names = checked_components(profile.as_os_str().as_bytes())
			.map_err(|_| SyncProfileStoreError::InvalidSelection)?;
		let owner = actor()?;
		let root = open_root()?;
		let mount = protected_mount(&root)?;
		let mut chain = vec![HeldComponent {
			name: Vec::new(),
			stamp: DirectoryStamp::observe(&root, owner)?,
			file: root,
		}];
		for name in names {
			let parent = chain
				.last()
				.ok_or(SyncProfileStoreError::InvalidSelection)?;
			let name = name.as_bytes().to_vec();
			let file = open_child(&parent.file, &name)?;
			let stamp = DirectoryStamp::observe(&file, owner)?;
			chain.push(HeldComponent { name, file, stamp });
		}
		let store = Self {
			chain,
			owner,
			mount,
		};
		let profile = store.profile().stamp;
		if profile.owner != owner || profile.mode != PRIVATE_DIRECTORY {
			return Err(SyncProfileStoreError::Unprotected);
		}
		store.recheck()?;
		Ok(store)
	}

	/// Exact native identity of the held profile.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.profile().stamp.identity
	}

	/// Positively rechecks the exact live profile, including all held names.
	///
	/// # Errors
	/// Refuses changed credentials, ancestry, mount, ownership or mode.
	pub fn recheck(&self) -> Result<(), SyncProfileStoreError> {
		if actor()? != self.owner {
			return Err(SyncProfileStoreError::Changed);
		}
		let root = open_root()?;
		let original = self.chain.first().ok_or(SyncProfileStoreError::Changed)?;
		if DirectoryStamp::observe(&original.file, self.owner)? != original.stamp
			|| DirectoryStamp::observe(&root, self.owner)? != original.stamp
			|| mount_id(&original.file)? != self.mount
			|| protected_mount(&root)? != self.mount
		{
			return Err(SyncProfileStoreError::Changed);
		}
		for pair in self.chain.windows(2) {
			let [parent, child] = pair else {
				return Err(SyncProfileStoreError::Changed);
			};
			let named = open_child(&parent.file, &child.name)?;
			if DirectoryStamp::observe(&child.file, self.owner)? != child.stamp
				|| DirectoryStamp::observe(&named, self.owner)? != child.stamp
				|| mount_id(&child.file)? != self.mount
				|| mount_id(&named)? != self.mount
			{
				return Err(SyncProfileStoreError::Changed);
			}
		}
		Ok(())
	}

	/// Acquires a seed-free read guard for exactly one existing selected record.
	///
	/// The application compares these exact bytes with its independent Init receipt.
	///
	/// # Errors
	/// Refuses invalid names, busy cooperating writers, unstable or unprotected
	/// observations and unbounded content.
	pub fn read(&self, id: [u8; 16]) -> Result<SyncProfileStoreRecord<'_>, SyncProfileStoreError> {
		let name = slot(id)?;
		let lease = self.lease(FlockOperation::NonBlockingLockShared)?;
		self.read_with_lease(name, lease, None)
	}

	/// Reads the fixed owner seed through the very same held profile for Init.
	///
	/// The caller must wipe both supplied buffers, including after refusal.
	/// The seed guard retains the exclusive cooperating profile lease.
	///
	/// # Errors
	/// Refuses unstable or unprotected observations and incomplete seed reads.
	pub fn open_seed(
		&self,
		bytes: &mut [u8; OWNER_SEED_BYTES],
		eof: &mut [u8; 1],
	) -> Result<SyncProfileSeed<'_>, SyncProfileStoreError> {
		let lease = self.lease(FlockOperation::NonBlockingLockExclusive)?;
		let pin = Pin::open(&lease, KEY_NAME.to_bytes(), self.owner, self.mount)?;
		if pin.stamp.extent != OWNER_SEED_BYTES {
			return Err(SyncProfileStoreError::InvalidExtent);
		}
		pin.read(&lease, bytes, eof)?;
		self.recheck()?;
		Ok(SyncProfileSeed {
			store: self,
			lease,
			pin,
		})
	}

	fn profile(&self) -> &HeldComponent {
		&self.chain[self.chain.len() - 1]
	}

	fn lease(&self, operation: FlockOperation) -> Result<File, SyncProfileStoreError> {
		self.recheck()?;
		let lease = open_child(&self.profile().file, b".")?;
		fs::flock(&lease, operation).map_err(|error| {
			if error == Errno::WOULDBLOCK {
				SyncProfileStoreError::Busy
			} else {
				error.into()
			}
		})?;
		if DirectoryStamp::observe(&lease, self.owner)? != self.profile().stamp
			|| mount_id(&lease)? != self.mount
		{
			return Err(SyncProfileStoreError::Changed);
		}
		self.recheck()?;
		Ok(lease)
	}

	fn read_with_lease(
		&self,
		name: Vec<u8>,
		lease: File,
		expected: Option<Stamp>,
	) -> Result<SyncProfileStoreRecord<'_>, SyncProfileStoreError> {
		let pin = Pin::open(&lease, &name, self.owner, self.mount)?;
		if expected.is_some_and(|stamp| pin.stamp != stamp) {
			return Err(SyncProfileStoreError::Changed);
		}
		check_extent(pin.stamp.extent)?;
		let mut bytes = vec![0; pin.stamp.extent];
		pin.read(&lease, &mut bytes, &mut [0])?;
		let record = SyncProfileStoreRecord {
			store: self,
			lease,
			pin,
			bytes,
		};
		record.recheck()?;
		Ok(record)
	}
}

/// Held, read-only selection record and cooperative profile lease.
pub struct SyncProfileStoreRecord<'store> {
	store: &'store SyncProfileStore,
	lease: File,
	pin: Pin,
	bytes: Vec<u8>,
}

impl SyncProfileStoreRecord<'_> {
	/// Exact private bytes captured from the held record.
	#[must_use]
	pub fn bytes(&self) -> &[u8] {
		&self.bytes
	}

	/// Rechecks full bytes, EOF, held identity and exact named binding.
	///
	/// # Errors
	/// Refuses if the seed-free record or its protected profile changed.
	pub fn recheck(&self) -> Result<(), SyncProfileStoreError> {
		self.store.recheck()?;
		let mut again = vec![0; self.bytes.len()];
		self.pin.read(&self.lease, &mut again, &mut [0])?;
		if again != self.bytes {
			return Err(SyncProfileStoreError::Changed);
		}
		self.store.recheck()
	}
}

/// Exclusive Init-only seed custody for this exact held profile.
pub struct SyncProfileSeed<'store> {
	store: &'store SyncProfileStore,
	lease: File,
	pin: Pin,
}

impl<'store> SyncProfileSeed<'store> {
	/// Writes the exact approved record to the absent fixed slot, then checks
	/// independent read-back and file and profile-directory barriers.
	///
	/// The application must first verify the explicit owner selection from the
	/// seed bytes it obtained from this guard. Wipe the supplied seed scratch
	/// and EOF buffer after success or refusal.
	///
	/// # Errors
	/// Refuses before a known incumbent or invalid selection. An error after
	/// exclusive creation retains the selected name without issuing a receipt.
	pub fn create(
		self,
		id: [u8; 16],
		exact: &[u8],
		expected_seed: &[u8; OWNER_SEED_BYTES],
		seed_check: &mut [u8; OWNER_SEED_BYTES],
		seed_eof: &mut [u8; 1],
	) -> Result<SyncProfileStoreRecord<'store>, SyncProfileStoreError> {
		let name = slot(id)?;
		check_extent(exact.len())?;
		self.recheck_seed(expected_seed, seed_check, seed_eof)?;
		let mut writer = match fs::openat2(
			&self.lease,
			&name,
			LEAF | OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
			PRIVATE_FILE,
			BELOW,
		) {
			Ok(file) => File::from(file),
			Err(Errno::EXIST) => return Err(SyncProfileStoreError::AlreadyExists),
			Err(error) => return Err(error.into()),
		};
		let result = (|| {
			let empty = Stamp::observe(&writer, self.store.owner, self.store.mount)?;
			if empty.extent != 0 {
				return Err(SyncProfileStoreError::Changed);
			}
			empty.require_name(&self.lease, &name)?;
			writer.write_all(exact)?;
			writer.sync_all()?;
			let written = Stamp::observe(&writer, self.store.owner, self.store.mount)?;
			if written.identity != empty.identity || written.extent != exact.len() {
				return Err(SyncProfileStoreError::Changed);
			}
			written.require_name(&self.lease, &name)?;
			drop(writer);
			let read_lease = self.lease.try_clone()?;
			let record = self
				.store
				.read_with_lease(name, read_lease, Some(written))?;
			if record.bytes() != exact {
				return Err(SyncProfileStoreError::Changed);
			}
			fs::fsync(&self.lease)?;
			self.recheck_seed(expected_seed, seed_check, seed_eof)?;
			record.recheck()?;
			Ok(record)
		})();
		result.map_err(|error| SyncProfileStoreError::CreationUnconfirmed(Box::new(error)))
	}

	/// Recheck the same held seed, exact expected bytes, and protected profile path.
	///
	/// The caller must wipe both supplied scratch buffers even after refusal.
	///
	/// # Errors
	/// Refuses incomplete seed reads or drift in held bytes, identity or ancestry.
	pub fn recheck_seed(
		&self,
		expected: &[u8; OWNER_SEED_BYTES],
		scratch: &mut [u8; OWNER_SEED_BYTES],
		eof: &mut [u8; 1],
	) -> Result<(), SyncProfileStoreError> {
		self.store.recheck()?;
		self.pin.read(&self.lease, scratch, eof)?;
		if scratch != expected {
			return Err(SyncProfileStoreError::Changed);
		}
		self.store.recheck()
	}
}

fn actor() -> Result<u32, SyncProfileStoreError> {
	let owner = geteuid();
	if owner.is_root() || owner != getuid() {
		return Err(SyncProfileStoreError::Unsupported);
	}
	Ok(owner.as_raw())
}

fn open_root() -> Result<File, SyncProfileStoreError> {
	Ok(fs::openat2(
		fs::CWD,
		c"/",
		DIRECTORY | OFlags::RDONLY,
		Mode::empty(),
		NO_LINKS,
	)?
	.into())
}

fn open_child(parent: &File, name: &[u8]) -> Result<File, SyncProfileStoreError> {
	Ok(fs::openat2(
		parent,
		name,
		DIRECTORY | OFlags::RDONLY,
		Mode::empty(),
		BELOW,
	)?
	.into())
}

fn protected_mount(root: &File) -> Result<u64, SyncProfileStoreError> {
	let mounts = MountObservations::capture()?;
	let id = mounts.whole_filesystem_mount(root)?;
	let record = mounts
		.record(id)
		.ok_or(SyncProfileStoreError::Unsupported)?;
	if record.mount_point != b"/"
		|| record.filesystem != b"ext4"
		|| fs::fstatfs(root)?.f_type != EXT4_SUPER_MAGIC
	{
		return Err(SyncProfileStoreError::Unsupported);
	}
	Ok(id)
}

fn slot(id: [u8; 16]) -> Result<Vec<u8>, SyncProfileStoreError> {
	if id == [0; 16] {
		return Err(SyncProfileStoreError::InvalidSelection);
	}
	const HEX: &[u8; 16] = b"0123456789abcdef";
	let mut name = b"managed-sync-".to_vec();
	for value in id {
		name.push(HEX[usize::from(value >> 4)]);
		name.push(HEX[usize::from(value & 15)]);
	}
	name.extend_from_slice(b".v1");
	Ok(name)
}

fn check_extent(extent: usize) -> Result<(), SyncProfileStoreError> {
	if !(1..=MAX_RECORD_BYTES).contains(&extent) {
		return Err(SyncProfileStoreError::InvalidExtent);
	}
	Ok(())
}
