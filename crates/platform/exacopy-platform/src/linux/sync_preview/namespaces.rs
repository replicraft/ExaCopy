use std::ffi::CStr;
use std::num::NonZeroU64;
use std::os::fd::{AsFd, OwnedFd};

use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

use super::SyncPreviewError;
use crate::linux::handle::FileIdentity;
use crate::linux::mount_observation::nonzero_decimal;

const PROC_ROOT_INODE: u64 = 1;
// Linux UAPI linux/magic.h. rustix 1.1.6 does not expose NSFS_MAGIC.
const NSFS_MAGIC: fs::FsWord = 0x6e73_6673;
const DIRECTORY_FLAGS: OFlags = OFlags::PATH.union(OFlags::DIRECTORY).union(OFlags::CLOEXEC);
const BELOW_PROC: ResolveFlags = ResolveFlags::BENEATH
	.union(ResolveFlags::NO_MAGICLINKS)
	.union(ResolveFlags::NO_XDEV);
// "user:[" plus twenty decimal digits, closing bracket and one spare byte.
const LINK_CAPACITY: usize = 28;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub(super) struct HeldNamespaces {
	mount: NamespacePin,
	user: NamespacePin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NamespaceFacts {
	pub(super) mount: FileIdentity,
	pub(super) user: FileIdentity,
}

impl HeldNamespaces {
	pub(super) fn current() -> Result<Self, SyncPreviewError> {
		let directory = namespace_directory()?;
		let pins = Self {
			mount: NamespaceKind::Mount.pin(&directory)?,
			user: NamespaceKind::User.pin(&directory)?,
		};
		if pins.facts().mount == pins.facts().user {
			return Err(SyncPreviewError::UnsupportedNamespace);
		}
		Ok(pins)
	}

	pub(super) const fn facts(&self) -> NamespaceFacts {
		NamespaceFacts {
			mount: self.mount.identity,
			user: self.user.identity,
		}
	}

	pub(super) fn recheck_current(&self) -> Result<(), SyncPreviewError> {
		self.mount.recheck()?;
		self.user.recheck()?;
		let current = Self::current()?;
		compare_facts(self.facts(), current.facts())
	}
}

fn compare_facts(
	expected: NamespaceFacts,
	current: NamespaceFacts,
) -> Result<(), SyncPreviewError> {
	if current != expected {
		return Err(SyncPreviewError::Changed);
	}
	Ok(())
}

fn namespace_directory() -> Result<OwnedFd, SyncPreviewError> {
	// Keep this in step with the stricter fixed paths in ProcMounts. Its private
	// descriptor has no namespace-link capability.
	let root = fs::openat2(
		fs::CWD,
		c"/proc",
		DIRECTORY_FLAGS,
		Mode::empty(),
		ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
	)
	.map_err(namespace_error)?;
	if fs::fstatfs(&root).map_err(namespace_error)?.f_type != fs::PROC_SUPER_MAGIC
		|| fs::fstat(&root).map_err(namespace_error)?.st_ino != PROC_ROOT_INODE
	{
		return Err(SyncPreviewError::UnsupportedNamespace);
	}
	// thread-self is a kernel-generated relative link to the calling thread.
	let thread = fs::openat2(
		&root,
		c"thread-self",
		DIRECTORY_FLAGS,
		Mode::empty(),
		BELOW_PROC,
	)
	.map_err(namespace_error)?;
	fs::openat2(
		&thread,
		c"ns",
		DIRECTORY_FLAGS,
		Mode::empty(),
		BELOW_PROC | ResolveFlags::NO_SYMLINKS,
	)
	.map_err(namespace_error)
}

#[derive(Clone, Copy)]
enum NamespaceKind {
	Mount,
	User,
}

impl NamespaceKind {
	const fn name(self) -> &'static CStr {
		match self {
			Self::Mount => c"mnt",
			Self::User => c"user",
		}
	}

	fn pin(self, directory: &OwnedFd) -> Result<NamespacePin, SyncPreviewError> {
		let before = self.link_inode(directory)?;
		// Following a magic link is confined to these two fixed children of the
		// verified procfs directory. A supported environment controls procfs mount
		// changes; the opened target must independently be an nsfs inode.
		let fd = fs::openat(
			directory,
			self.name(),
			OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY,
			Mode::empty(),
		)
		.map_err(namespace_error)?;
		let identity = namespace_identity(&fd)?;
		let after = self.link_inode(directory)?;
		if before != after || identity.inode() != before.get() {
			return Err(SyncPreviewError::Changed);
		}
		Ok(NamespacePin { fd, identity })
	}

	fn link_inode(self, directory: &OwnedFd) -> Result<NonZeroU64, SyncPreviewError> {
		let link = fs::openat2(
			directory,
			self.name(),
			OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
			Mode::empty(),
			BELOW_PROC | ResolveFlags::NO_SYMLINKS,
		)
		.map_err(namespace_error)?;
		if FileType::from_raw_mode(fs::fstat(&link).map_err(namespace_error)?.st_mode)
			!= FileType::Symlink
		{
			return Err(SyncPreviewError::UnsupportedNamespace);
		}
		let mut buffer = [0; LINK_CAPACITY];
		let length = fs::readlinkat_raw(&link, c"", &mut buffer[..]).map_err(namespace_error)?;
		parse_link(self, &buffer[..length]).ok_or(SyncPreviewError::UnsupportedNamespace)
	}
}

fn parse_link(kind: NamespaceKind, bytes: &[u8]) -> Option<NonZeroU64> {
	let prefix = match kind {
		NamespaceKind::Mount => b"mnt:[".as_slice(),
		NamespaceKind::User => b"user:[".as_slice(),
	};
	let digits = bytes.strip_prefix(prefix)?.strip_suffix(b"]")?;
	if digits.len() > 20 {
		return None;
	}
	NonZeroU64::new(nonzero_decimal(digits)?)
}

#[derive(Debug)]
struct NamespacePin {
	fd: OwnedFd,
	identity: FileIdentity,
}

impl NamespacePin {
	fn recheck(&self) -> Result<(), SyncPreviewError> {
		if namespace_identity(&self.fd)? != self.identity {
			return Err(SyncPreviewError::Changed);
		}
		Ok(())
	}
}

fn namespace_identity(fd: impl AsFd) -> Result<FileIdentity, SyncPreviewError> {
	let fd = fd.as_fd();
	if fs::fstatfs(fd).map_err(namespace_error)?.f_type != NSFS_MAGIC {
		return Err(SyncPreviewError::UnsupportedNamespace);
	}
	let stat = fs::fstat(fd).map_err(namespace_error)?;
	let identity = FileIdentity::from_stat(&stat);
	if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || identity.inode() == 0 {
		return Err(SyncPreviewError::UnsupportedNamespace);
	}
	Ok(identity)
}

fn namespace_error(error: Errno) -> SyncPreviewError {
	match error {
		Errno::NOSYS
		| Errno::NOTSUP
		| Errno::INVAL
		| Errno::NOENT
		| Errno::LOOP
		| Errno::XDEV
		| Errno::NOTDIR => SyncPreviewError::UnsupportedNamespace,
		_ => SyncPreviewError::System(error.into()),
	}
}
