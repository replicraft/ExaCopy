use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;

use exacopy_endpoint::{IoError, MAX_INTERRUPTED_RETRIES, UnixComponent};
use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags, Stat};
use rustix::io::Errno;
use rustix::path::DecInt;

use super::handle::FileIdentity;

mod observation;
pub(super) mod xattrs;

pub use observation::{SourceObservation, SourceTimestamp};
pub use xattrs::ExtendedAttributes;

/// Failure to bind a read capability, select a regular file, or read a range.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReadError {
	/// The supplied root descriptor refers to an object other than a directory.
	NotDirectory,
	/// The selected inode is a directory or special file.
	NotRegularFile,
	/// The descriptor reopening path failed procfs validation.
	UnsupportedProcfs,
	/// The reopened descriptor has a different identity or type from the pinned file.
	IdentityChanged,
	/// The observed regular-file size cannot be represented by the adapter.
	InvalidLength,
	/// The filesystem reported an invalid nanosecond fraction.
	InvalidTimestamp,
	/// The held inode's size, modification time, change time, or basic metadata changed.
	SourceChanged,
	/// A positioned read returned data beyond the captured extent.
	UnexpectedDataAfterEnd,
	/// The visible extended-attribute name list exceeds the Linux VFS limit.
	ExtendedAttributeListTooLarge,
	/// The kernel could not inspect the extended-attribute name list.
	ExtendedAttributesUnreadable(io::Error),
	/// The requested range extends beyond the length captured at open.
	RangeOutsideFile,
	/// Exact positional I/O could not complete.
	Io(IoError),
	/// A filesystem syscall failed.
	System(io::Error),
}

impl fmt::Display for ReadError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::NotDirectory => formatter.write_str("read root must be a directory"),
			Self::NotRegularFile => formatter.write_str("source must be a regular file"),
			Self::UnsupportedProcfs => {
				formatter.write_str("descriptor reopening requires trusted procfs")
			}
			Self::IdentityChanged => {
				formatter.write_str("reopened file does not match the pinned file")
			}
			Self::InvalidLength => formatter.write_str("file length exceeds the supported range"),
			Self::InvalidTimestamp => formatter.write_str("source has an invalid timestamp"),
			Self::SourceChanged => formatter.write_str("source metadata changed after open"),
			Self::UnexpectedDataAfterEnd => {
				formatter.write_str("source returned data beyond its recorded length")
			}
			Self::ExtendedAttributeListTooLarge => {
				formatter.write_str("source extended-attribute name list exceeds the Linux limit")
			}
			Self::ExtendedAttributesUnreadable(error) => {
				write!(
					formatter,
					"source extended-attribute inspection failed ({error})"
				)
			}
			Self::RangeOutsideFile => {
				formatter.write_str("read range exceeds the recorded file length")
			}
			Self::Io(error) => write!(formatter, "source read failed ({error})"),
			Self::System(error) => {
				write!(formatter, "source descriptor operation failed ({error})")
			}
		}
	}
}

impl Error for ReadError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Io(error) => Some(error),
			Self::ExtendedAttributesUnreadable(error) | Self::System(error) => Some(error),
			_ => None,
		}
	}
}

impl From<Errno> for ReadError {
	fn from(error: Errno) -> Self {
		Self::System(error.into())
	}
}

const CHILD_RESOLUTION: ResolveFlags = ResolveFlags::BENEATH
	.union(ResolveFlags::NO_MAGICLINKS)
	.union(ResolveFlags::NO_SYMLINKS)
	.union(ResolveFlags::NO_XDEV);

/// A held Linux directory from which a reader may select one child by name.
pub struct ReadRoot {
	directory: File,
	identity: FileIdentity,
}

impl fmt::Debug for ReadRoot {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.debug_struct("ReadRoot").finish_non_exhaustive()
	}
}

impl ReadRoot {
	/// Bind an already authorized directory descriptor.
	///
	/// # Errors
	///
	/// Fails if the descriptor cannot be inspected or refers to a non-directory.
	pub fn from_directory(directory: File) -> Result<Self, ReadError> {
		let stat = fs::fstat(&directory)?;
		if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
			return Err(ReadError::NotDirectory);
		}
		Ok(Self {
			directory,
			identity: FileIdentity::from_stat(&stat),
		})
	}

	/// Returns the native identity observed for the held directory descriptor.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.identity
	}

	/// Open a regular child with read-only rights, refusing links and mount crossings.
	///
	/// Reopening the pinned inode requires the calling thread's Linux procfs
	/// descriptor directory. The kernel and mount namespace are trusted during
	/// this operation.
	///
	/// # Errors
	///
	/// Fails for disallowed entry types or paths, unsupported kernel resolution or
	/// procfs, an identity mismatch, invalid file metadata, or a filesystem error.
	pub fn open_regular(&self, name: UnixComponent<'_>) -> Result<SourceFile, ReadError> {
		let pinned = fs::openat2(
			&self.directory,
			name.as_bytes(),
			OFlags::PATH | OFlags::CLOEXEC,
			Mode::empty(),
			CHILD_RESOLUTION,
		)?;
		let (file, stat) = reopen_regular_read_only(&pinned)?;
		Ok(SourceFile {
			file,
			observation: SourceObservation::capture(&stat)?,
		})
	}
}

/// A read-only regular-file descriptor and the basic metadata captured at open.
///
/// Reads observe live file contents. Other writers can change those contents,
/// and reading may update access times.
pub struct SourceFile {
	file: File,
	observation: SourceObservation,
}

impl fmt::Debug for SourceFile {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("SourceFile")
			.field("length", &self.len())
			.finish_non_exhaustive()
	}
}

impl SourceFile {
	/// Return the identity of the held descriptor.
	#[must_use]
	pub fn identity(&self) -> FileIdentity {
		self.observation.identity()
	}

	/// Return the length captured at open.
	#[must_use]
	pub fn len(&self) -> u64 {
		self.observation.len()
	}

	/// Return whether the file was empty at open.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.observation.is_empty()
	}

	/// Return the observation captured when this inode was opened.
	#[must_use]
	pub fn observation(&self) -> SourceObservation {
		self.observation
	}

	/// Compare the held inode with the observation captured at open.
	///
	/// Access-time changes are ignored because ordinary reads can update that timestamp.
	/// An equal observation is a live-source change check with the filesystem's timestamp
	/// resolution and visibility limits.
	///
	/// # Errors
	/// Fails if the descriptor cannot be inspected or a tracked field changed.
	pub fn recheck_observation(&self) -> Result<(), ReadError> {
		let stat = fs::fstat(&self.file)?;
		self.observation.recheck(SourceObservation::capture(&stat)?)
	}

	/// Checks that a positioned read encounters EOF at the captured logical length.
	///
	/// Some virtual inodes report a nominal size unrelated to their stream.
	/// This one-byte probe detects extra data without including it in the copy.
	///
	/// # Errors
	/// Reports unexpected data, an unsupported probe, or a read failure.
	pub fn check_logical_eof(&self) -> Result<(), ReadError> {
		check_logical_eof(&self.file, self.len())
	}

	/// Inspect whether this process can see extended attribute names on the held inode.
	///
	/// The Linux descriptor query obtains the list size without allocating a name buffer.
	/// Permissions can hide some namespaces. Linux's regular file has one logical byte
	/// stream in this adapter; attributes are metadata.
	///
	/// # Errors
	/// Fails when inspection is unreadable or the visible list exceeds the Linux limit.
	pub fn extended_attributes(&self) -> Result<ExtendedAttributes, ReadError> {
		xattrs::inspect(&self.file)
	}

	/// Fill a buffer from the given offset without changing the file cursor.
	///
	/// An empty range at or before the recorded end succeeds. An error may
	/// leave bytes already read in the buffer.
	///
	/// # Errors
	///
	/// Fails if the range exceeds the recorded length or if exact positional
	/// I/O fails, including end of file after the source shrinks.
	pub fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), ReadError> {
		let length = u64::try_from(buffer.len()).map_err(|_| ReadError::RangeOutsideFile)?;
		if offset
			.checked_add(length)
			.is_none_or(|end| end > self.len())
		{
			return Err(ReadError::RangeOutsideFile);
		}

		exacopy_endpoint::read_exact_at(offset, buffer, |position, remaining| {
			self.file.read_at(remaining, position)
		})
		.map_err(ReadError::Io)
	}
}

pub(super) fn check_logical_eof(file: &File, length: u64) -> Result<(), ReadError> {
	let mut remaining_retries = MAX_INTERRUPTED_RETRIES;
	loop {
		match file.read_at(&mut [0], length) {
			Ok(0) => return Ok(()),
			Ok(_) => return Err(ReadError::UnexpectedDataAfterEnd),
			Err(error) if error.kind() == io::ErrorKind::Interrupted && remaining_retries > 0 => {
				remaining_retries -= 1;
			}
			Err(error) => return Err(ReadError::System(error)),
		}
	}
}

pub(super) fn reopen_regular_read_only(pinned: &impl AsFd) -> Result<(File, Stat), ReadError> {
	reopen_regular(pinned, OFlags::RDONLY)
}

pub(super) fn reopen_regular_without_atime(pinned: &impl AsFd) -> Result<(File, Stat), ReadError> {
	reopen_regular(pinned, OFlags::RDONLY | OFlags::NOATIME)
}

pub(super) fn reopen_regular_for_append(pinned: &impl AsFd) -> Result<(File, Stat), ReadError> {
	reopen_regular(pinned, OFlags::RDWR | OFlags::APPEND | OFlags::NOATIME)
}

fn reopen_regular(pinned: &impl AsFd, flags: OFlags) -> Result<(File, Stat), ReadError> {
	let pinned_stat = fs::fstat(pinned)?;
	if FileType::from_raw_mode(pinned_stat.st_mode) != FileType::RegularFile {
		return Err(ReadError::NotRegularFile);
	}

	let proc = fs::openat2(
		fs::CWD,
		c"/proc",
		OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
		Mode::empty(),
		ResolveFlags::NO_SYMLINKS,
	)?;
	// Inode 1 identifies the procfs root, including when the procfs root is bind mounted.
	const PROC_ROOT_INODE: u64 = 1;
	if fs::fstatfs(&proc)?.f_type != fs::PROC_SUPER_MAGIC
		|| fs::fstat(&proc)?.st_ino != PROC_ROOT_INODE
	{
		return Err(ReadError::UnsupportedProcfs);
	}

	// thread-self is a kernel-generated relative symlink that selects the
	// calling thread's file table. Reject mount crossings anywhere below procfs.
	let descriptors = fs::openat2(
		&proc,
		c"thread-self/fd",
		OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
		Mode::empty(),
		ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_XDEV,
	)?;
	let descriptor_name = DecInt::from_fd(pinned);
	let link = fs::openat2(
		&descriptors,
		descriptor_name.as_c_str(),
		OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
		Mode::empty(),
		CHILD_RESOLUTION,
	)?;
	if FileType::from_raw_mode(fs::fstat(&link)?.st_mode) != FileType::Symlink {
		return Err(ReadError::UnsupportedProcfs);
	}

	// Deliberately follow the procfs magic link to the still-held regular file.
	// This step trusts that privileged actors do not change procfs mounts during
	// the check and reopen. Only the proc descriptor name is resolved here.
	let file = fs::openat(
		&descriptors,
		descriptor_name.as_c_str(),
		OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY | flags,
		Mode::empty(),
	)?;
	let stat = fs::fstat(&file)?;
	if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
		|| FileIdentity::from_stat(&stat) != FileIdentity::from_stat(&pinned_stat)
	{
		return Err(ReadError::IdentityChanged);
	}
	Ok((File::from(file), stat))
}
