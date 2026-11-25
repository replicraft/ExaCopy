use std::ffi::{CStr, OsStr};
use std::fmt;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use exacopy_journal::{LinuxFileIdentity, OwnerProfileId, RootCapabilityId};
use exacopy_platform::linux::FileIdentity;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use rustix::process::geteuid;
use rustix::rand::{GetRandomFlags, getrandom};
use uuid::Builder;
use zeroize::Zeroizing;

use crate::linux_path::split;

const KEY_NAME: &CStr = c"owner.seed";
const SEED_BYTES: usize = ed25519_dalek::SECRET_KEY_LENGTH;
const DIRECTORY_MODE: Mode = Mode::RUSR.union(Mode::WUSR).union(Mode::XUSR);
const SEED_MODE: Mode = Mode::RUSR.union(Mode::WUSR);
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
	.union(OFlags::DIRECTORY)
	.union(OFlags::CLOEXEC);
const FILE_FLAGS: OFlags = OFlags::CLOEXEC
	.union(OFlags::NOFOLLOW)
	.union(OFlags::NONBLOCK);
const MAX_KERNEL_RANDOM_BYTES: usize = 256;

pub(crate) struct LocalProfile {
	id: OwnerProfileId,
	signer: SigningKey,
	seed: LinuxFileIdentity,
	_seed_file: File,
}

impl LocalProfile {
	pub(crate) fn open(path: &Path) -> Result<Self, ProfileError> {
		let (parent, name) = split(path).map_err(|_| ProfileError::InvalidPath)?;
		let parent = fs::open(
			parent,
			OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
			Mode::empty(),
		)?;
		check_parent(&parent)?;
		let name = OsStr::from_bytes(name.as_bytes());
		let directory = open_profile_directory(&parent, name)?;
		let before = fs::statat(&directory, KEY_NAME, AtFlags::SYMLINK_NOFOLLOW)?;
		validate_seed(&before, SEED_BYTES)?;
		let mut file = File::from(fs::openat(
			&directory,
			KEY_NAME,
			FILE_FLAGS | OFlags::RDONLY,
			Mode::empty(),
		)?);
		check_same(&before, &fs::fstat(&file)?)?;
		let mut seed = Zeroizing::new([0; SEED_BYTES]);
		file.read_exact(seed.as_mut())?;
		let mut extra = Zeroizing::new([0; 1]);
		if file.read(extra.as_mut())? != 0 {
			return Err(ProfileError::UnsafeSeed);
		}
		check_same(&before, &fs::fstat(&file)?)?;
		check_same(
			&before,
			&fs::statat(&directory, KEY_NAME, AtFlags::SYMLINK_NOFOLLOW)?,
		)?;
		check_directory_name(&parent, name, &directory)?;

		let signer = SigningKey::from_bytes(&seed);
		let id = OwnerProfileId::from_bytes(identifier(
			"ExaCopy local CLI profile ID v1",
			signer.verifying_key().as_bytes(),
		))
		.map_err(|_| ProfileError::Identifier)?;
		Ok(Self {
			id,
			signer,
			seed: LinuxFileIdentity::new(before.st_dev, before.st_ino),
			_seed_file: file,
		})
	}

	pub(crate) const fn id(&self) -> OwnerProfileId {
		self.id
	}

	pub(crate) const fn signer(&self) -> &SigningKey {
		&self.signer
	}

	pub(crate) fn verification_key(&self) -> VerifyingKey {
		self.signer.verifying_key()
	}

	pub(crate) fn root_id(&self, identity: FileIdentity) -> Result<RootCapabilityId, ProfileError> {
		let mut context = [0; 48];
		context[..32].copy_from_slice(self.verification_key().as_bytes());
		context[32..40].copy_from_slice(&identity.device().to_le_bytes());
		context[40..].copy_from_slice(&identity.inode().to_le_bytes());
		RootCapabilityId::from_bytes(identifier("ExaCopy local CLI root ID v1", &context))
			.map_err(|_| ProfileError::Identifier)
	}

	pub(crate) fn is_seed(&self, identity: LinuxFileIdentity) -> bool {
		self.seed == identity
	}
}

pub(crate) fn init(path: &Path) -> Result<(), ProfileError> {
	let (parent, name) = split(path).map_err(|_| ProfileError::InvalidPath)?;
	let parent = fs::open(parent, DIRECTORY_FLAGS, Mode::empty())?;
	check_parent(&parent)?;
	let mut seed = Zeroizing::new([0; SEED_BYTES]);
	kernel_random(seed.as_mut())?;

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
	file.write_all(seed.as_ref())?;
	let written = fs::fstat(&file)?;
	validate_seed(&written, SEED_BYTES)?;
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

fn check_parent(parent: &OwnedFd) -> Result<(), ProfileError> {
	let stat = fs::fstat(parent)?;
	let mode = Mode::from_raw_mode(stat.st_mode);
	if (stat.st_uid != geteuid().as_raw() && stat.st_uid != 0)
		|| (mode.intersects(Mode::WGRP | Mode::WOTH) && !mode.contains(Mode::SVTX))
	{
		return Err(ProfileError::UnsafeParent);
	}
	Ok(())
}

fn open_profile_directory(parent: &OwnedFd, name: &OsStr) -> Result<OwnedFd, ProfileError> {
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
) -> Result<(), ProfileError> {
	let held = fs::fstat(directory)?;
	if held.st_uid != geteuid().as_raw() || Mode::from_raw_mode(held.st_mode) != DIRECTORY_MODE {
		return Err(ProfileError::UnsafeDirectory);
	}
	check_same(&held, &fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)?)
}

fn validate_seed(stat: &Stat, length: usize) -> Result<(), ProfileError> {
	if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
		|| stat.st_uid != geteuid().as_raw()
		|| Mode::from_raw_mode(stat.st_mode) != SEED_MODE
		|| stat.st_nlink != 1
		|| usize::try_from(stat.st_size).ok() != Some(length)
	{
		return Err(ProfileError::UnsafeSeed);
	}
	Ok(())
}

fn check_same(held: &Stat, observed: &Stat) -> Result<(), ProfileError> {
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
		return Err(ProfileError::IdentityChanged);
	}
	Ok(())
}

fn identifier(domain: &str, material: &[u8]) -> [u8; 16] {
	let mut bytes = [0; 16];
	blake3::Hasher::new_derive_key(domain)
		.update(material)
		.finalize_xof()
		.fill(&mut bytes);
	Builder::from_custom_bytes(bytes).into_uuid().into_bytes()
}

pub(crate) fn kernel_random(output: &mut [u8]) -> Result<(), ProfileError> {
	// Linux returns the entire request once the kernel RNG is initialized for
	// these bounded requests. Refuse a short read without using partial entropy.
	if output.len() > MAX_KERNEL_RANDOM_BYTES
		|| getrandom(&mut *output, GetRandomFlags::empty())? != output.len()
	{
		return Err(ProfileError::Random);
	}
	Ok(())
}

#[derive(Debug)]
pub(crate) enum ProfileError {
	InvalidPath,
	UnsafeParent,
	UnsafeDirectory,
	UnsafeSeed,
	IdentityChanged,
	Identifier,
	Random,
	Io(io::Error),
}

impl ProfileError {
	pub(crate) fn init_exit_code(&self) -> u8 {
		match self {
			Self::InvalidPath => 2,
			Self::Io(error) if error.raw_os_error() == Some(Errno::EXIST.raw_os_error()) => 3,
			Self::UnsafeParent
			| Self::UnsafeDirectory
			| Self::UnsafeSeed
			| Self::IdentityChanged => 8,
			_ => 4,
		}
	}
}

impl From<Errno> for ProfileError {
	fn from(error: Errno) -> Self {
		Self::Io(error.into())
	}
}

impl From<io::Error> for ProfileError {
	fn from(error: io::Error) -> Self {
		Self::Io(error)
	}
}

impl fmt::Display for ProfileError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidPath => formatter.write_str("expected a named profile directory"),
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
			Self::Identifier => formatter.write_str("could not bind the profile or root identity"),
			Self::Random => formatter.write_str("kernel randomness was incomplete"),
			Self::Io(error) => write!(formatter, "{error}"),
		}
	}
}
