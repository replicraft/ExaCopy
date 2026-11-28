use std::ffi::{CStr, OsStr};
use std::fmt;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;

use exacopy_endpoint::UnixComponent;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use rustix::process::geteuid;
use rustix::rand::{GetRandomFlags, getrandom};

use super::{FileIdentity, handle::pin_selected_directory};

pub(super) const KEY_NAME: &CStr = c"owner.seed";
/// The exact byte length of an owner seed in the local profile layout.
pub const OWNER_SEED_BYTES: usize = 32;
const DIRECTORY_MODE: Mode = Mode::RUSR.union(Mode::WUSR).union(Mode::XUSR);
const SEED_MODE: Mode = Mode::RUSR.union(Mode::WUSR);
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
	.union(OFlags::DIRECTORY)
	.union(OFlags::CLOEXEC);
const FILE_FLAGS: OFlags = OFlags::CLOEXEC
	.union(OFlags::NOFOLLOW)
	.union(OFlags::NONBLOCK);
const MAX_KERNEL_RANDOM_BYTES: usize = 256;

/// The seed's native identity, bound to its still-held read-only file handle.
pub struct HeldOwnerSeed {
	identity: FileIdentity,
	_file: File,
}

impl HeldOwnerSeed {
	/// Opens the selected private profile and reads its exact seed bytes.
	///
	/// The caller supplies scratch for the seed and the EOF check. Either
	/// buffer may contain secret bytes even on error and should be wiped.
	///
	/// # Errors
	/// Refuses unsafe parents, directory and seed metadata, changed
	/// observations, and incomplete reads.
	pub fn open(
		parent: &OsStr,
		name: UnixComponent<'_>,
		seed: &mut [u8; OWNER_SEED_BYTES],
		eof_probe: &mut [u8; 1],
	) -> Result<Self, OwnerSeedError> {
		let parent = pin_selected_directory(parent)?;
		check_parent(&parent)?;
		let name = OsStr::from_bytes(name.as_bytes());
		let directory = open_profile_directory(&parent, name)?;
		let before = fs::statat(&directory, KEY_NAME, AtFlags::SYMLINK_NOFOLLOW)?;
		validate_seed(&before, OWNER_SEED_BYTES)?;
		let mut file = File::from(fs::openat(
			&directory,
			KEY_NAME,
			FILE_FLAGS | OFlags::RDONLY,
			Mode::empty(),
		)?);
		check_same(&before, &fs::fstat(&file)?)?;
		file.read_exact(seed)?;
		if file.read(eof_probe)? != 0 {
			return Err(OwnerSeedError::UnsafeSeed);
		}
		check_same(&before, &fs::fstat(&file)?)?;
		check_same(
			&before,
			&fs::statat(&directory, KEY_NAME, AtFlags::SYMLINK_NOFOLLOW)?,
		)?;
		check_directory_name(&parent, name, &directory)?;

		Ok(Self {
			identity: FileIdentity::from_stat(&before),
			_file: file,
		})
	}

	/// Returns the seed identity while keeping its backing handle live.
	#[must_use]
	pub const fn identity(&self) -> FileIdentity {
		self.identity
	}
}

/// Creates an absent private profile and synchronizes the seed and namespace.
///
/// The caller supplies seed scratch and should wipe it after the operation,
/// including on error. A partially created profile is left in place.
///
/// # Errors
/// Refuses unsafe parents, incumbents, incomplete entropy, changed
/// observations, and file or namespace barrier failures.
pub fn initialize_owner_seed(
	parent: &OsStr,
	name: UnixComponent<'_>,
	seed: &mut [u8; OWNER_SEED_BYTES],
) -> Result<(), OwnerSeedError> {
	let parent = fs::open(parent, DIRECTORY_FLAGS, Mode::empty())?;
	check_parent(&parent)?;
	kernel_random(seed)?;

	let name = OsStr::from_bytes(name.as_bytes());
	fs::mkdirat(&parent, name, DIRECTORY_MODE)?;
	let directory = open_profile_directory(&parent, name)?;
	let mut file = File::from(fs::openat(
		&directory,
		KEY_NAME,
		FILE_FLAGS | OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
		SEED_MODE,
	)?);
	validate_seed(&fs::fstat(&file)?, 0)?;
	file.write_all(seed)?;
	let written = fs::fstat(&file)?;
	validate_seed(&written, OWNER_SEED_BYTES)?;
	check_same(
		&written,
		&fs::statat(&directory, KEY_NAME, AtFlags::SYMLINK_NOFOLLOW)?,
	)?;
	check_directory_name(&parent, name, &directory)?;
	file.sync_all()?;
	fs::fsync(&directory)?;
	fs::fsync(&parent)?;
	check_directory_name(&parent, name, &directory)
}

fn check_parent(parent: &OwnedFd) -> Result<(), OwnerSeedError> {
	let stat = fs::fstat(parent)?;
	let mode = Mode::from_raw_mode(stat.st_mode);
	if (stat.st_uid != geteuid().as_raw() && stat.st_uid != 0)
		|| (mode.intersects(Mode::WGRP | Mode::WOTH) && !mode.contains(Mode::SVTX))
	{
		return Err(OwnerSeedError::UnsafeParent);
	}
	Ok(())
}

fn open_profile_directory(parent: &OwnedFd, name: &OsStr) -> Result<OwnedFd, OwnerSeedError> {
	let directory = fs::openat(
		parent,
		name,
		DIRECTORY_FLAGS | OFlags::NOFOLLOW,
		Mode::empty(),
	)?;
	check_directory_name(parent, name, &directory)?;
	Ok(directory)
}

fn check_directory_name(
	parent: &OwnedFd,
	name: &OsStr,
	directory: &OwnedFd,
) -> Result<(), OwnerSeedError> {
	let held = fs::fstat(directory)?;
	if held.st_uid != geteuid().as_raw() || Mode::from_raw_mode(held.st_mode) != DIRECTORY_MODE {
		return Err(OwnerSeedError::UnsafeDirectory);
	}
	check_same(&held, &fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?)
}

fn validate_seed(stat: &Stat, length: usize) -> Result<(), OwnerSeedError> {
	if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
		|| stat.st_uid != geteuid().as_raw()
		|| Mode::from_raw_mode(stat.st_mode) != SEED_MODE
		|| stat.st_nlink != 1
		|| usize::try_from(stat.st_size).ok() != Some(length)
	{
		return Err(OwnerSeedError::UnsafeSeed);
	}
	Ok(())
}

fn check_same(held: &Stat, observed: &Stat) -> Result<(), OwnerSeedError> {
	if held.st_dev != observed.st_dev
		|| held.st_ino != observed.st_ino
		|| held.st_uid != observed.st_uid
		|| held.st_mode != observed.st_mode
		|| held.st_nlink != observed.st_nlink
		|| held.st_size != observed.st_size
		|| held.st_ctime != observed.st_ctime
		|| held.st_ctime_nsec != observed.st_ctime_nsec
		|| held.st_mtime != observed.st_mtime
		|| held.st_mtime_nsec != observed.st_mtime_nsec
	{
		return Err(OwnerSeedError::IdentityChanged);
	}
	Ok(())
}

/// Fills a bounded buffer from the native Linux random generator.
///
/// # Errors
/// Refuses requests over 256 bytes, native failures and short returns.
pub fn kernel_random(output: &mut [u8]) -> Result<(), OwnerSeedError> {
	// Linux returns the entire request once the kernel RNG is initialized for
	// these bounded requests. Refuse a short read without using partial entropy.
	if output.len() > MAX_KERNEL_RANDOM_BYTES
		|| getrandom(&mut *output, GetRandomFlags::empty())? != output.len()
	{
		return Err(OwnerSeedError::Random);
	}
	Ok(())
}

/// Refusal of the private owner-seed or bounded entropy operation.
#[derive(Debug)]
#[non_exhaustive]
pub enum OwnerSeedError {
	/// The parent does not meet the managed-owner and sticky-bit contract.
	UnsafeParent,
	/// The private profile directory is not owned by the current user in mode 0700.
	UnsafeDirectory,
	/// The seed name does not identify an owner-only single-link regular file.
	UnsafeSeed,
	/// The held and name-relative observations differ.
	IdentityChanged,
	/// The random request exceeds the bound or completed short.
	Random,
	/// A native operation failed.
	Io(io::Error),
}

impl From<Errno> for OwnerSeedError {
	fn from(error: Errno) -> Self {
		Self::Io(error.into())
	}
}

impl From<io::Error> for OwnerSeedError {
	fn from(error: io::Error) -> Self {
		Self::Io(error)
	}
}

impl fmt::Display for OwnerSeedError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::UnsafeParent => formatter.write_str("the profile requires a managed parent"),
			Self::UnsafeDirectory => {
				formatter.write_str("profile directory must be owner-only (0700)")
			}
			Self::UnsafeSeed => formatter.write_str(
				"profile seed must be a single-link owner-only (0600) 32-byte regular file",
			),
			Self::IdentityChanged => {
				formatter.write_str("profile identity or observed metadata changed")
			}
			Self::Random => formatter.write_str("kernel randomness was incomplete"),
			Self::Io(error) => write!(formatter, "{error}"),
		}
	}
}

impl std::error::Error for OwnerSeedError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Io(error) => Some(error),
			_ => None,
		}
	}
}

#[cfg(test)]
mod tests;
