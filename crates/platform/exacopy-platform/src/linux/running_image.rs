use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::FileExt as _;

use exacopy_endpoint::ReadView;
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, PROC_SUPER_MAGIC, ResolveFlags};

use super::SourceObservation;

#[cfg(test)]
mod tests;

const MAX_BYTES: u64 = 512 * 1024 * 1024;
const DIRECTORY: OFlags = OFlags::RDONLY
	.union(OFlags::DIRECTORY)
	.union(OFlags::NOFOLLOW)
	.union(OFlags::CLOEXEC);

/// Read-only, bounded view of the current Linux process's original executable.
pub struct RunningExecutable {
	process: OwnedFd,
	executable: File,
	observation: SourceObservation,
}

impl RunningExecutable {
	/// Opens the kernel's executable link under a checked proc directory for this process.
	/// # Errors
	/// Refuses unsupported procfs, foreign or over-limit files, or inconsistent observations.
	pub fn open() -> io::Result<Self> {
		let proc = fs::open("/proc", DIRECTORY, Mode::empty())?;
		let pid = std::process::id().to_string();
		let mut self_link = [0; 16];
		let count = fs::readlinkat_raw(&proc, "self", &mut self_link[..])?;
		if fs::fstatfs(&proc)?.f_type != PROC_SUPER_MAGIC
			|| self_link.get(..count) != Some(pid.as_bytes())
		{
			return Err(unavailable());
		}
		let process = fs::openat2(
			&proc,
			pid.as_str(),
			DIRECTORY,
			Mode::empty(),
			ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_SYMLINKS,
		)?;
		if fs::fstatfs(&process)?.f_type != PROC_SUPER_MAGIC {
			return Err(unavailable());
		}
		let executable = open_image(&process)?;
		let observation = facts(&executable)?;
		let held = Self {
			process,
			executable,
			observation,
		};
		held.recheck_observation()?;
		Ok(held)
	}
}

impl ReadView for RunningExecutable {
	type Error = io::Error;

	fn length(&self) -> u64 {
		self.observation.len()
	}

	fn recheck_observation(&self) -> io::Result<()> {
		let mut eof = [0];
		if self.executable.read_at(&mut eof, self.length())? != 0 {
			return Err(unavailable());
		}
		self.observation
			.recheck(facts(&self.executable)?)
			.map_err(io::Error::other)?;
		self.observation
			.recheck(facts(&open_image(&self.process)?)?)
			.map_err(io::Error::other)
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
		if !u64::try_from(bytes.len())
			.ok()
			.and_then(|count| offset.checked_add(count))
			.is_some_and(|end| end <= self.length())
		{
			return Err(unavailable());
		}
		self.executable.read_exact_at(bytes, offset)
	}
}

fn open_image(process: impl AsFd) -> io::Result<File> {
	let metadata = fs::statat(&process, "exe", AtFlags::SYMLINK_NOFOLLOW)?;
	if FileType::from_raw_mode(metadata.st_mode) != FileType::Symlink {
		return Err(unavailable());
	}
	// This fixed kernel magic link is the one intentional link-following operation.
	let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK;
	Ok(fs::openat(process, "exe", flags, Mode::empty())?.into())
}

fn facts(file: &File) -> io::Result<SourceObservation> {
	let observed = SourceObservation::capture(&fs::fstat(file)?).map_err(io::Error::other)?;
	if !(1..=MAX_BYTES).contains(&observed.len()) {
		return Err(unavailable());
	}
	Ok(observed)
}

fn unavailable() -> io::Error {
	io::Error::other("the exact running Linux executable could not be established")
}
