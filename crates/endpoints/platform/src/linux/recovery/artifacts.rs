use std::ffi::OsStr;

use rustix::io::Errno;

use crate::linux::job::{
	CHECKPOINTS, FIRST_SEGMENT, JOURNAL, OWNER, PLAN, RECEIPT, RECEIPTS, check_page_length,
	checkpoint_page_name,
};

use super::{
	PrivateDirectory, RecoveryFile, RecoveryJob, StageError, check_absent, open_checked_record,
};

impl RecoveryJob<'_> {
	/// Opens the private `owner.cbor` record read-only.
	///
	/// # Errors
	/// Fails for unsafe, missing, or detached records or enclosing directories.
	pub fn open_owner(&self) -> Result<RecoveryFile, StageError> {
		self.open_record(None, OsStr::new(OWNER))
	}

	/// Opens the private canonical `plan.cbor` record read-only.
	///
	/// # Errors
	/// Fails for unsafe, missing, or detached records or enclosing directories.
	pub fn open_plan(&self) -> Result<RecoveryFile, StageError> {
		self.open_record(None, OsStr::new(PLAN))
	}

	/// Opens the fixed first journal segment read-only.
	///
	/// # Errors
	/// Fails for unsafe, missing, or detached records or enclosing directories.
	pub fn open_first_segment(&self) -> Result<RecoveryFile, StageError> {
		self.open_record(Some(OsStr::new(JOURNAL)), OsStr::new(FIRST_SEGMENT))
	}

	/// Opens an ordinal checkpoint page read-only under the caller's job lease.
	/// # Errors
	/// Rejects invalid ordinals, unsafe or missing records, and out-of-bounds lengths.
	pub fn open_checkpoint_page(&self, ordinal: u32) -> Result<RecoveryFile, StageError> {
		let name = checkpoint_page_name(ordinal)?;
		let file = self.open_record(Some(OsStr::new(CHECKPOINTS)), OsStr::new(&name))?;
		check_page_length(file.len())?;
		Ok(file)
	}

	/// Opens the fixed receipt record read-only.
	///
	/// # Errors
	/// Fails for unsafe, missing, or detached records or enclosing directories.
	pub fn open_receipt(&self) -> Result<RecoveryFile, StageError> {
		self.open_record(Some(OsStr::new(RECEIPTS)), OsStr::new(RECEIPT))
	}

	pub(in crate::linux) fn open_optional_owner(&self) -> Result<Option<RecoveryFile>, StageError> {
		self.open_optional_record(None, OsStr::new(OWNER))
	}

	pub(in crate::linux) fn open_optional_plan(&self) -> Result<Option<RecoveryFile>, StageError> {
		self.open_optional_record(None, OsStr::new(PLAN))
	}

	pub(in crate::linux) fn open_optional_first_segment(
		&self,
	) -> Result<Option<RecoveryFile>, StageError> {
		self.open_optional_record(Some(OsStr::new(JOURNAL)), OsStr::new(FIRST_SEGMENT))
	}

	pub(in crate::linux) fn open_optional_receipt(
		&self,
	) -> Result<Option<RecoveryFile>, StageError> {
		self.open_optional_record(Some(OsStr::new(RECEIPTS)), OsStr::new(RECEIPT))
	}

	fn open_record(
		&self,
		child_name: Option<&OsStr>,
		name: &OsStr,
	) -> Result<RecoveryFile, StageError> {
		self.open_optional_record(child_name, name)?
			.ok_or_else(|| Errno::NOENT.into())
	}

	fn open_optional_record(
		&self,
		child_name: Option<&OsStr>,
		name: &OsStr,
	) -> Result<Option<RecoveryFile>, StageError> {
		self.recheck()?;
		let mount = self.root.mount;
		let parent = &self.directory.file;
		let file = if let Some(child_name) = child_name {
			match PrivateDirectory::open(parent, child_name, mount)? {
				Some(child) => {
					let file = open_checked_record(&child.file, name, mount)?;
					child.recheck(parent, child_name, mount)?;
					file
				}
				None => {
					check_absent(parent, child_name)?;
					None
				}
			}
		} else {
			open_checked_record(parent, name, mount)?
		};
		self.recheck()?;
		Ok(file)
	}
}
