use std::error::Error;
use std::fmt;
use std::io;

use exacopy_endpoint::IoError;
use rustix::io::Errno;

use super::super::source::ReadError;

#[cfg(test)]
mod tests;

/// Failure while preparing, writing, flushing, or closing a stage.
#[derive(Debug)]
#[non_exhaustive]
pub enum StageError {
	/// Exclusive creation found an existing entry and left it untouched.
	AlreadyExists,
	/// A directory failed its required type, ownership, or permissions check.
	UnsafeDirectory,
	/// The staged file failed its type, ownership, permissions, or link-count check.
	UnsafeFile,
	/// The staged object's identity, mount, or observed contents changed.
	IdentityChanged,
	/// The file length falls outside the supported signed offset range.
	InvalidLength,
	/// No successful full file barrier followed the most recent write or resize.
	Unflushed,
	/// The file barrier failed. The stage remains private and unusable.
	BarrierFailed(io::Error),
	/// An earlier file barrier failed. The stage requires reconciliation.
	PriorBarrierFailure,
	/// Exact positional writing failed.
	Write(IoError),
	/// The pinned inode could not be reopened and checked for read-back.
	ReadBack(ReadError),
	/// A staging syscall failed.
	System(io::Error),
}

impl StageError {
	pub(super) fn on_create(source: Errno) -> Self {
		match source {
			Errno::EXIST => Self::AlreadyExists,
			_ => Self::from(source),
		}
	}
}

impl From<Errno> for StageError {
	fn from(source: Errno) -> Self {
		Self::System(source.into())
	}
}

impl fmt::Display for StageError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::AlreadyExists => f.write_str("exclusive staging name already exists"),
			Self::UnsafeDirectory => f.write_str("directory failed the managed staging policy"),
			Self::UnsafeFile => f.write_str("file failed the private staging policy"),
			Self::IdentityChanged => f.write_str("staged object identity or observations changed"),
			Self::InvalidLength => f.write_str("file length is outside the supported offset range"),
			Self::Unflushed => f.write_str("stage writes require a successful full file barrier"),
			Self::BarrierFailed(source) => write!(f, "stage file synchronization failed: {source}"),
			Self::PriorBarrierFailure => f.write_str("stage file barrier previously failed"),
			Self::Write(source) => write!(f, "could not write the private stage: {source}"),
			Self::ReadBack(source) => write!(f, "could not reopen the pinned stage: {source}"),
			Self::System(source) => write!(f, "staging syscall failed: {source}"),
		}
	}
}

impl Error for StageError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::ReadBack(source) => Some(source),
			Self::Write(source) => Some(source),
			Self::BarrierFailed(source) | Self::System(source) => Some(source),
			_ => None,
		}
	}
}

/// Why exclusive publication did not return success.
#[derive(Debug)]
#[non_exhaustive]
pub enum PublishError {
	/// The exclusive rename found an incumbent and preserved both entries.
	Conflict,
	/// The kernel or mount could not perform the required exclusive rename.
	Unsupported(io::Error),
	/// The rename outcome was not established. Reconcile the actual namespace.
	Uncertain(io::Error),
	/// A pre-rename check rejected the stage or its namespace.
	StageChanged(StageError),
	/// The model authorization belongs to a different job, entry, epoch, or stage.
	BindingMismatch,
	/// The rename succeeded, but a required directory barrier failed.
	BarriersFailed(DirectoryBarriersError),
}

impl fmt::Display for PublishError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Conflict => f.write_str("the target name already exists"),
			Self::Unsupported(source) => write!(f, "exclusive rename is unsupported: {source}"),
			Self::Uncertain(source) => write!(f, "exclusive rename outcome is uncertain: {source}"),
			Self::StageChanged(source) => write!(f, "stage rejected before publication: {source}"),
			Self::BindingMismatch => {
				f.write_str("publication authorization names a different stage")
			}
			Self::BarriersFailed(source) => {
				write!(
					f,
					"exclusive rename succeeded but directory synchronization failed: {source}"
				)
			}
		}
	}
}

impl Error for PublishError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Unsupported(source) | Self::Uncertain(source) => Some(source),
			Self::StageChanged(source) => Some(source),
			Self::BarriersFailed(source) => Some(source),
			Self::Conflict | Self::BindingMismatch => None,
		}
	}
}

/// Failed synchronization of at least one directory after a successful rename.
#[derive(Debug)]
#[non_exhaustive]
pub enum DirectoryBarriersError {
	/// The private staging directory barrier failed.
	Stage(io::Error),
	/// The destination directory barrier failed.
	Destination(io::Error),
	/// Synchronization failed for both affected directories.
	Both {
		/// The private staging directory's error.
		stage: io::Error,
		/// The destination directory's error.
		destination: io::Error,
	},
}

impl fmt::Display for DirectoryBarriersError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Stage(source) => write!(f, "stage directory: {source}"),
			Self::Destination(source) => write!(f, "destination directory: {source}"),
			Self::Both { stage, destination } => {
				write!(
					f,
					"stage directory: {stage}, destination directory: {destination}"
				)
			}
		}
	}
}

impl Error for DirectoryBarriersError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Stage(source) | Self::Destination(source) => Some(source),
			Self::Both { .. } => None,
		}
	}
}
