use std::fs::File;
use std::io::Write as _;

use exacopy_endpoint::{ReadView as _, UnixComponent};
use exacopy_platform::linux::{NamedReadView, ReadRoot};
use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use rustix::process::geteuid;

use super::{BELOW, Failure, Kind};

const PRIVATE_FILE: Mode = Mode::RUSR.union(Mode::WUSR);
const FILE_FLAGS: OFlags = OFlags::CLOEXEC
	.union(OFlags::NOFOLLOW)
	.union(OFlags::NONBLOCK);

pub(super) struct Record {
	file: File,
	stamp: Stat,
}

pub(super) fn create(
	parent: &File,
	name: UnixComponent<'_>,
	content: &[u8],
) -> Result<Record, Failure> {
	let mut file = match fs::openat2(
		parent,
		name.as_bytes(),
		FILE_FLAGS | OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
		PRIVATE_FILE,
		BELOW,
	) {
		Ok(file) => File::from(file),
		Err(error @ Errno::EXIST) => return Err(Failure::with(Kind::AlreadyExists, error)),
		Err(error) => return Err(Failure::with(Kind::BundleIo, error)),
	};
	let empty = fs::fstat(&file).map_err(Failure::bundle_open)?;
	private_regular(&empty, 0)?;
	ensure_name(parent, name, &empty)?;
	file.write_all(content).map_err(Failure::bundle_io)?;
	file.sync_all().map_err(Failure::bundle_io)?;
	let stamp = fs::fstat(&file).map_err(Failure::bundle_open)?;
	private_regular(&stamp, content.len())?;
	let record = Record { file, stamp };
	check_named(parent, name, &record)?;
	Ok(record)
}

pub(super) fn read_existing(
	parent: &File,
	name: UnixComponent<'_>,
	expected: &[u8],
) -> Result<Record, Failure> {
	let original = fs::statat(parent, name.as_bytes(), AtFlags::SYMLINK_NOFOLLOW)
		.map_err(Failure::bundle_open)?;
	private_regular(&original, expected.len())?;
	let root = ReadRoot::from_directory(parent.try_clone().map_err(Failure::bundle_io)?)
		.map_err(Failure::reuse_read)?;
	let reader = NamedReadView::open(&root, name).map_err(Failure::reuse_read)?;
	if (reader.identity().device(), reader.identity().inode()) != (original.st_dev, original.st_ino)
		|| reader.length() != expected.len() as u64
	{
		return Err(Failure::plain(Kind::BundleConflict));
	}
	let mut bytes = vec![0; expected.len()];
	reader.recheck_observation().map_err(Failure::reuse_read)?;
	reader
		.read_exact_at(0, &mut bytes)
		.map_err(Failure::reuse_read)?;
	reader.recheck_observation().map_err(Failure::reuse_read)?;
	if bytes != expected {
		return Err(Failure::plain(Kind::BundleConflict));
	}
	ensure_name(parent, name, &original)?;
	let file = File::from(
		fs::openat2(
			parent,
			name.as_bytes(),
			FILE_FLAGS | OFlags::RDONLY,
			Mode::empty(),
			BELOW,
		)
		.map_err(Failure::bundle_open)?,
	);
	let record = Record {
		file,
		stamp: original,
	};
	check_named(parent, name, &record)?;
	record.file.sync_all().map_err(Failure::bundle_io)?;
	reader.recheck_observation().map_err(Failure::reuse_read)?;
	check_named(parent, name, &record)?;
	Ok(record)
}

pub(super) fn check_named(
	parent: &File,
	name: UnixComponent<'_>,
	record: &Record,
) -> Result<(), Failure> {
	let held = fs::fstat(&record.file).map_err(Failure::bundle_open)?;
	if !same_stamp(&held, &record.stamp) {
		return Err(Failure::plain(Kind::BundleConflict));
	}
	ensure_name(parent, name, &held)
}

fn ensure_name(parent: &File, name: UnixComponent<'_>, held: &Stat) -> Result<(), Failure> {
	let named = fs::statat(parent, name.as_bytes(), AtFlags::SYMLINK_NOFOLLOW)
		.map_err(Failure::bundle_open)?;
	if !same_stamp(&named, held) {
		return Err(Failure::plain(Kind::BundleConflict));
	}
	Ok(())
}

fn private_regular(observed: &Stat, length: usize) -> Result<(), Failure> {
	if FileType::from_raw_mode(observed.st_mode) != FileType::RegularFile
		|| Mode::from_raw_mode(observed.st_mode) != PRIVATE_FILE
		|| observed.st_uid != geteuid().as_raw()
		|| observed.st_nlink != 1
		|| usize::try_from(observed.st_size) != Ok(length)
	{
		return Err(Failure::plain(Kind::BundleConflict));
	}
	Ok(())
}

fn same_stamp(left: &Stat, right: &Stat) -> bool {
	(
		left.st_dev,
		left.st_ino,
		left.st_mode,
		left.st_uid,
		left.st_gid,
		left.st_nlink,
		left.st_size,
	) == (
		right.st_dev,
		right.st_ino,
		right.st_mode,
		right.st_uid,
		right.st_gid,
		right.st_nlink,
		right.st_size,
	) && (
		left.st_ctime,
		left.st_ctime_nsec,
		left.st_mtime,
		left.st_mtime_nsec,
	) == (
		right.st_ctime,
		right.st_ctime_nsec,
		right.st_mtime,
		right.st_mtime_nsec,
	)
}

#[cfg(test)]
mod tests;
