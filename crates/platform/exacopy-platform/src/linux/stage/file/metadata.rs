use std::fs::File;
use std::io;

use exacopy_endpoint::linux_apply::{ApplyRole, ApplyStep};

use rustix::fs::{self, Mode, Stat, Timespec, Timestamps};

use super::super::super::source::{SourceObservation, SourceTimestamp};
use super::{ClosedStage, StageError, check_content_stamp};

mod checked_publication;
pub use checked_publication::{CheckedStageError, NativePublishedStage};

#[cfg(test)]
mod tests;

pub(super) const ORDINARY_PERMISSIONS: u32 = 0o777;

impl ClosedStage<'_> {
	pub(in crate::linux) fn guard_stage_seal<G>(
		&self,
		enter: impl FnOnce() -> io::Result<G>,
	) -> Result<(), StageError> {
		self.check_current()?;
		self.location.directory.sync_directory_admitted(enter)?;
		self.check_current()
	}

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
	pub fn apply_metadata(self, source: SourceObservation) -> Result<Self, StageError> {
		self.apply_metadata_with_access_time(source, source.accessed_at())
	}

	/// Applies and verifies required metadata using a previously captured access time.
	///
	/// A resumed copy can preserve the pre-read access time from its authenticated
	/// journal while taking the remaining metadata from the current observation.
	///
	/// # Errors
	/// Has the same requirements and failure effects as [`Self::apply_metadata`].
	pub fn apply_metadata_with_access_time(
		self,
		source: SourceObservation,
		accessed_at: SourceTimestamp,
	) -> Result<Self, StageError> {
		self.apply_metadata_admitted_with_access_time(source, accessed_at, |_| Ok(()))
	}

	pub(in crate::linux) fn apply_metadata_admitted_with_access_time<G>(
		mut self,
		source: SourceObservation,
		accessed_at: SourceTimestamp,
		enter: impl Fn(ApplyStep) -> io::Result<G>,
	) -> Result<Self, StageError> {
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
			last_access: as_timespec(accessed_at)?,
			last_modification: as_timespec(source.modified_at())?,
		};
		{
			let _guard = enter(ApplyStep::SetStagePermissions).map_err(StageError::Admission)?;
			fs::fchmod(&self.file, mode)?;
		}
		{
			let _guard = enter(ApplyStep::SetStageTimes).map_err(StageError::Admission)?;
			fs::futimens(&self.file, &times)?;
		}
		let before = self.location.check_named_file(mode)?;
		check_metadata(&before, source, accessed_at)?;

		{
			let _guard = enter(ApplyStep::Sync(ApplyRole::Stage)).map_err(StageError::Admission)?;
			fs::fsync(&self.file).map_err(|source| StageError::BarrierFailed(source.into()))?;
		}
		let after = self.location.check_named_file(mode)?;
		check_content_stamp(&before, &after)?;
		check_metadata(&after, source, accessed_at)?;
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

fn check_metadata(
	stat: &Stat,
	source: SourceObservation,
	accessed_at: SourceTimestamp,
) -> Result<(), StageError> {
	if u64::try_from(stat.st_size) != Ok(source.len())
		|| stat.st_uid != source.owner()
		|| stat.st_gid != source.group()
		|| stat.st_atime != accessed_at.seconds()
		|| u32::try_from(stat.st_atime_nsec) != Ok(accessed_at.nanoseconds())
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
