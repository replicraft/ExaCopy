use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io;

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags};
use rustix::process::geteuid;

use super::super::owner_seed::{KEY_NAME, OWNER_SEED_BYTES};
use super::super::{DestinationRoot, FileIdentity, ReadError, ReadRoot, StageError};

/// One held source, destination or profile parent used by a Plan export.
pub struct PlanInputDirectory(pub(super) File);

impl PlanInputDirectory {
	/// Binds the selected parent with the export's existing path resolution policy.
	///
	/// # Errors
	/// Reports a failed or non-directory open.
	pub fn open(path: &OsStr) -> io::Result<Self> {
		let directory = fs::open(
			path,
			OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
			Mode::empty(),
		)?;
		Ok(Self(File::from(directory)))
	}

	/// Clones this held parent into the ordinary read-root capability.
	///
	/// # Errors
	/// Reports a failed clone or root admission check.
	pub fn read_root(&self) -> Result<ReadRoot, ReadError> {
		let directory = self.0.try_clone().map_err(ReadError::System)?;
		ReadRoot::from_directory(directory)
	}

	/// Clones this held parent into the ordinary destination capability.
	///
	/// # Errors
	/// Reports a failed clone or managed-root admission check.
	pub fn destination_root(&self) -> Result<DestinationRoot, StageError> {
		let directory = self.0.try_clone().map_err(StageError::System)?;
		DestinationRoot::from_directory(directory)
	}

	/// Checks the selected profile seed's name and captures its change stamp.
	///
	/// The caller supplies the existing expected identity policy.
	/// This observation does not read seed data.
	///
	/// # Errors
	/// Reports a failed syscall or a seed name outside the required contract.
	pub fn observe_seed(
		&self,
		accepts: impl FnOnce(FileIdentity) -> bool,
	) -> Result<PlanSeedStamp, PlanSeedError> {
		let named = fs::statat(&self.0, KEY_NAME, AtFlags::SYMLINK_NOFOLLOW)
			.map_err(|error| PlanSeedError::Io(error.into()))?;
		if !accepts(FileIdentity::from_stat(&named))
			|| FileType::from_raw_mode(named.st_mode) != FileType::RegularFile
			|| Mode::from_raw_mode(named.st_mode) != Mode::RUSR | Mode::WUSR
			|| named.st_uid != geteuid().as_raw()
			|| named.st_nlink != 1
			|| usize::try_from(named.st_size) != Ok(OWNER_SEED_BYTES)
		{
			return Err(PlanSeedError::Unsafe);
		}
		Ok(PlanSeedStamp {
			mtime: (named.st_mtime.into(), named.st_mtime_nsec.into()),
			ctime: (named.st_ctime.into(), named.st_ctime_nsec.into()),
		})
	}
}

/// The exact change and modification timestamp observations of the admitted seed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PlanSeedStamp {
	mtime: (i128, i128),
	ctime: (i128, i128),
}

/// Failure to observe the selected private seed name during Plan export.
#[derive(Debug)]
#[non_exhaustive]
pub enum PlanSeedError {
	/// The selected name or observed seed metadata was refused.
	Unsafe,
	/// Native name observation failed.
	Io(io::Error),
}

impl fmt::Display for PlanSeedError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Unsafe => formatter.write_str("plan seed observation refused"),
			Self::Io(error) => error.fmt(formatter),
		}
	}
}

impl std::error::Error for PlanSeedError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Unsafe => None,
			Self::Io(error) => Some(error),
		}
	}
}

#[cfg(test)]
#[path = "../../../tests/unit/plan_inputs.rs"]
mod tests;
