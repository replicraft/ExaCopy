use std::fs::File;

use super::super::MountObservations;
use rustix::fs::{self, Mode, OFlags};
use rustix::process::geteuid;

use super::PlanBundleError;

const MAX_ANCESTORS: usize = 256;
const PARENT_FLAGS: OFlags = OFlags::PATH
	.union(OFlags::DIRECTORY)
	.union(OFlags::CLOEXEC)
	.union(OFlags::NOFOLLOW);

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Directory {
	key: (u64, u64),
	mount: u64,
	mode: Mode,
	owner: u32,
}

pub(super) fn ancestry(
	start: &File,
	mounts: &MountObservations,
	require_protection: bool,
) -> Result<Vec<Directory>, PlanBundleError> {
	let mut held = start.try_clone().map_err(PlanBundleError::io)?;
	let mut chain = Vec::new();
	for _ in 0..MAX_ANCESTORS {
		let info = fs::fstat(&held).map_err(PlanBundleError::bundle_open)?;
		let mount = mounts
			.whole_filesystem_mount(&held)
			.map_err(PlanBundleError::mount_observation)?;
		let entry = Directory {
			key: (info.st_dev, info.st_ino),
			mount,
			mode: Mode::from_raw_mode(info.st_mode),
			owner: info.st_uid,
		};
		if require_protection {
			check_protected(entry)?;
		}
		if chain.last() == Some(&entry) {
			return Ok(chain);
		}
		if chain.contains(&entry) {
			return Err(PlanBundleError::Scope(None));
		}
		chain.push(entry);
		// The component is internal and fixed. No path supplied by a record
		// participates in the walk from the actual held directory.
		held = File::from(
			fs::openat(&held, c"..", PARENT_FLAGS, Mode::empty())
				.map_err(PlanBundleError::bundle_open)?,
		);
	}
	Err(PlanBundleError::Scope(None))
}

fn check_protected(observed: Directory) -> Result<(), PlanBundleError> {
	let owner = geteuid().as_raw();
	if observed.owner != 0 && observed.owner != owner
		|| (observed.mode.intersects(Mode::WGRP | Mode::WOTH)
			&& !observed.mode.contains(Mode::SVTX))
	{
		return Err(PlanBundleError::Unsafe(None));
	}
	Ok(())
}

pub(super) fn require_disjoint(
	output: &[Directory],
	protected: [&File; 3],
	mounts: &MountObservations,
) -> Result<(), PlanBundleError> {
	let selected = output.first().ok_or(PlanBundleError::Scope(None))?;
	for root in protected {
		let chain = ancestry(root, mounts, false)?;
		let scope = chain.first().ok_or(PlanBundleError::Scope(None))?;
		if output.iter().any(|entry| entry.key == scope.key)
			|| chain.iter().any(|entry| entry.key == selected.key)
		{
			return Err(PlanBundleError::Scope(None));
		}
	}
	Ok(())
}
