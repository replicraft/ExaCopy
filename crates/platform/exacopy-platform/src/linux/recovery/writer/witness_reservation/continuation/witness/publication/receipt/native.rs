use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::FileExt as _;

use rustix::fs;

use super::WitnessReceiptNames;
use crate::linux::recovery::{check_absent, mount_id, open_path};
use crate::linux::source::{check_logical_eof, reopen_regular_without_atime};
use crate::linux::stage::{FILE_MODE, check_no_visible_attributes};
use crate::linux::{SourceObservation, StageError};

pub(super) fn reopen_sealed(
	original: &File,
	before: SourceObservation,
	bytes: &[u8],
	mount: u64,
) -> Result<(File, SourceObservation), StageError> {
	let first = exact_receipt(original, before, bytes, 0, mount)?;
	let (file, _) = reopen_regular_without_atime(original).map_err(StageError::ReadBack)?;
	let independent = exact_receipt(&file, before, bytes, 0, mount)?;
	first.recheck(independent).map_err(StageError::ReadBack)?;
	Ok((file, independent))
}

pub(super) fn exact_receipt(
	file: &File,
	original: SourceObservation,
	bytes: &[u8],
	links: u64,
	mount: u64,
) -> Result<SourceObservation, StageError> {
	let stamp = capture(file)?;
	if stamp.identity() != original.identity()
		|| stamp.len() != bytes.len() as u64
		|| stamp.mode() != FILE_MODE.as_raw_mode()
		|| stamp.owner() != original.owner()
		|| stamp.group() != original.group()
		|| stamp.link_count() != links
		|| mount_id(file)? != mount
	{
		return Err(StageError::IdentityChanged);
	}
	check_no_visible_attributes(file)?;
	let mut buffer = [0_u8; super::RECEIPT_CAPACITY as usize];
	let observed = &mut buffer[..bytes.len()];
	file.read_exact_at(observed, 0)
		.map_err(StageError::System)?;
	if observed != bytes {
		return Err(StageError::IdentityChanged);
	}
	check_logical_eof(file, stamp.len()).map_err(StageError::ReadBack)?;
	stamp
		.recheck(capture(file)?)
		.map_err(StageError::ReadBack)?;
	Ok(stamp)
}

pub(super) fn confirm_transition(
	old: SourceObservation,
	new: SourceObservation,
) -> Result<(), StageError> {
	// The exact gate-owned namespace effect may update ctime (and link count
	// for the initial link). All immutable file facts are checked separately.
	if old.modified_at() != new.modified_at() || old.accessed_at() != new.accessed_at() {
		return Err(StageError::IdentityChanged);
	}
	Ok(())
}

pub(super) fn pin_receipt_name(
	job: &File,
	mount: u64,
	stamp: SourceObservation,
	names: &WitnessReceiptNames,
	final_name: bool,
) -> Result<File, StageError> {
	let (present, absent) = if final_name {
		(&names.final_name[..], &names.pending[..])
	} else {
		(&names.pending[..], &names.final_name[..])
	};
	check_absent(job, OsStr::from_bytes(absent))?;
	let held = open_path(job, OsStr::from_bytes(present))?.ok_or(StageError::IdentityChanged)?;
	if mount_id(&held)? != mount {
		return Err(StageError::IdentityChanged);
	}
	stamp
		.recheck(capture(&held)?)
		.map_err(StageError::ReadBack)?;
	check_absent(job, OsStr::from_bytes(absent))?;
	Ok(held)
}

pub(super) fn require_absent(job: &File, names: &WitnessReceiptNames) -> Result<(), StageError> {
	check_absent(job, OsStr::from_bytes(&names.pending))?;
	check_absent(job, OsStr::from_bytes(&names.final_name))
}

pub(super) fn capture(file: &File) -> Result<SourceObservation, StageError> {
	SourceObservation::capture(&fs::fstat(file)?).map_err(StageError::ReadBack)
}

pub(super) fn link_pending(
	file: &File,
	job: &File,
	names: &WitnessReceiptNames,
) -> Result<(), StageError> {
	fs::linkat(
		file,
		c"",
		job,
		OsStr::from_bytes(&names.pending),
		fs::AtFlags::EMPTY_PATH,
	)?;
	Ok(())
}

pub(super) fn rename_pending(job: &File, names: &WitnessReceiptNames) -> Result<(), StageError> {
	fs::renameat_with(
		job,
		OsStr::from_bytes(&names.pending),
		job,
		OsStr::from_bytes(&names.final_name),
		fs::RenameFlags::NOREPLACE,
	)?;
	Ok(())
}
