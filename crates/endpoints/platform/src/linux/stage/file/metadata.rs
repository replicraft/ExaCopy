use std::fs::File;

use rustix::fs::{self, Mode, Stat, Timespec, Timestamps};

use super::super::super::source::{SourceObservation, SourceTimestamp};
use super::{ClosedStage, StageError, check_content_stamp};

#[cfg(test)]
mod tests;

const ORDINARY_PERMISSIONS: u32 = 0o777;

impl ClosedStage<'_> {
	/// Applies and verifies ordinary permission bits and source access and modification times.
	///
	/// Call after completing read-back. The pinned descriptor remains read-only for file data.
	/// Existing UID and GID must already match. Both before and after metadata application,
	/// the destination's visible extended attribute inventory must be empty.
	///
	/// # Errors
	///
	/// Rejects unsupported metadata, changed stage state, failed required syscalls and
	/// metadata read-back mismatches. On error the capability is consumed and the private
	/// entry remains for reconciliation.
	pub fn apply_metadata(mut self, source: SourceObservation) -> Result<Self, StageError> {
		self.check_current()?;
		if source.mode() & !ORDINARY_PERMISSIONS != 0 {
			return Err(StageError::UnsupportedMode);
		}
		if self.stat.st_uid != source.owner() || self.stat.st_gid != source.group() {
			return Err(StageError::DifferentOwnership);
		}
		if self.length != source.len() {
			return Err(StageError::MetadataMismatch);
		}
		check_no_visible_attributes(&self.file)?;

		let mode = Mode::from_raw_mode(source.mode());
		let times = Timestamps {
			last_access: as_timespec(source.accessed_at())?,
			last_modification: as_timespec(source.modified_at())?,
		};
		fs::fchmod(&self.file, mode)?;
		fs::futimens(&self.file, &times)?;
		let before = self.location.check_named_file(mode)?;
		check_metadata(&before, source)?;

		fs::fsync(&self.file).map_err(|source| StageError::BarrierFailed(source.into()))?;
		let after = self.location.check_named_file(mode)?;
		check_content_stamp(&before, &after)?;
		check_metadata(&after, source)?;
		check_no_visible_attributes(&self.file)?;
		self.stat = after;
		self.metadata_applied = true;

		Ok(self)
	}
}

fn as_timespec(timestamp: SourceTimestamp) -> Result<Timespec, StageError> {
	let nanos = i32::try_from(timestamp.nanoseconds()).map_err(|_| StageError::MetadataMismatch)?;
	Ok(Timespec {
		tv_sec: timestamp.seconds(),
		tv_nsec: nanos.into(),
	})
}

fn check_metadata(stat: &Stat, source: SourceObservation) -> Result<(), StageError> {
	if u64::try_from(stat.st_size) != Ok(source.len())
		|| stat.st_uid != source.owner()
		|| stat.st_gid != source.group()
		|| stat.st_atime != source.accessed_at().seconds()
		|| u32::try_from(stat.st_atime_nsec) != Ok(source.accessed_at().nanoseconds())
		|| stat.st_mtime != source.modified_at().seconds()
		|| u32::try_from(stat.st_mtime_nsec) != Ok(source.modified_at().nanoseconds())
	{
		return Err(StageError::MetadataMismatch);
	}
	Ok(())
}

pub(in crate::linux) fn check_no_visible_attributes(file: &File) -> Result<(), StageError> {
	let size = fs::flistxattr_query(file)
		.map_err(|source| StageError::ExtendedAttributesUnavailable(source.into()))?;
	if size != 0 {
		return Err(StageError::UnexpectedExtendedAttributes);
	}
	Ok(())
}
