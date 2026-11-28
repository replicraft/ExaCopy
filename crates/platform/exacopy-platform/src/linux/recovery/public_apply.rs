use std::ffi::OsStr;
use std::fmt;
use std::fs::File;

use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::linux_recovery::{
	ApplyNamesSelection, HeldPublicApplyRecords, PublicApplyReadView,
};

use crate::linux::ProcessCrashEligibility;
use crate::linux::job::{OWNER, PLAN};

use super::{
	FIRST_SEGMENT, FilePolicy, JOURNAL, PrivateDirectory, RECEIPT, RECEIPTS, RecoveryFile,
	RecoveryReadLease, StageError, check_absent, open_checked_record, recheck_regular,
};

mod names;

pub use names::PublicApplyRecoveryNames;

/// Read-only reconciliation view of one original shared Linux job lease.
pub struct PublicApplyRecoveryView<'view> {
	lease: &'view RecoveryReadLease<'view>,
	eligibility: Option<&'view ProcessCrashEligibility<'view>>,
}

impl fmt::Debug for PublicApplyRecoveryView<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("PublicApplyRecoveryView")
			.field("job", &self.lease.job().identity())
			.finish_non_exhaustive()
	}
}

impl RecoveryReadLease<'_> {
	/// Selects a public-apply read-only view borrowing this original shared lease.
	/// Without matched current native eligibility, the selected stage and public
	/// names receive metadata observations only.
	#[must_use]
	pub fn public_apply_view<'view>(
		&'view self,
		eligibility: Option<&'view ProcessCrashEligibility<'view>>,
	) -> PublicApplyRecoveryView<'view> {
		PublicApplyRecoveryView {
			lease: self,
			eligibility,
		}
	}
}

impl PublicApplyReadView for PublicApplyRecoveryView<'_> {
	type Record = RecoveryFile;
	type Error = StageError;
	type Records<'view>
		= PublicApplyRecoveryRecords<'view>
	where
		Self: 'view;
	type Names<'view>
		= PublicApplyRecoveryNames<'view>
	where
		Self: 'view;

	fn identities(&self) -> (JobFileIdentity, JobFileIdentity) {
		let job = self.lease.job();
		(job.identity().into(), job.destination_identity().into())
	}

	fn hold_apply_records(&self) -> Result<Self::Records<'_>, Self::Error> {
		self.lease.recheck()?;
		let job = self.lease.job();
		let parent = &job.directory.file;
		let mount = job.root.mount;
		let records = PublicApplyRecoveryRecords {
			lease: self.lease,
			owner: open_checked_record(parent, OsStr::new(OWNER), mount)?,
			plan: open_checked_record(parent, OsStr::new(PLAN), mount)?,
			journal: FixedChild::open(parent, JOURNAL, FIRST_SEGMENT, mount)?,
			receipt: FixedChild::open(parent, RECEIPTS, RECEIPT, mount)?,
		};
		records.recheck_records()?;
		Ok(records)
	}

	fn pin_apply_names(
		&self,
		selection: ApplyNamesSelection<'_>,
	) -> Result<Self::Names<'_>, Self::Error> {
		PublicApplyRecoveryNames::open(self.lease, self.eligibility, selection)
	}

	fn open_apply_checkpoint(&self, ordinal: u32) -> Result<Self::Record, Self::Error> {
		self.lease.recheck()?;
		let record = self.lease.job().open_checkpoint_page(ordinal)?;
		record.check_logical_eof().map_err(StageError::ReadBack)?;
		self.lease.recheck()?;
		Ok(record)
	}
}

/// Fixed records and their original parent directories on the shared read lease.
pub struct PublicApplyRecoveryRecords<'view> {
	lease: &'view RecoveryReadLease<'view>,
	owner: Option<RecoveryFile>,
	plan: Option<RecoveryFile>,
	journal: FixedChild,
	receipt: FixedChild,
}

impl fmt::Debug for PublicApplyRecoveryRecords<'_> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("PublicApplyRecoveryRecords")
			.field("job", &self.lease.job().identity())
			.finish_non_exhaustive()
	}
}

impl HeldPublicApplyRecords for PublicApplyRecoveryRecords<'_> {
	type Record = RecoveryFile;
	type Error = StageError;

	fn owner(&self) -> Option<&Self::Record> {
		self.owner.as_ref()
	}

	fn plan(&self) -> Option<&Self::Record> {
		self.plan.as_ref()
	}

	fn segment(&mut self) -> Option<&mut Self::Record> {
		self.journal.record.as_mut()
	}

	fn receipt(&self) -> Option<&Self::Record> {
		self.receipt.record.as_ref()
	}

	fn recheck_records(&self) -> Result<(), Self::Error> {
		self.lease.recheck()?;
		let job = self.lease.job();
		let parent = &job.directory.file;
		let mount = job.root.mount;
		let owner = OsStr::new(OWNER);
		let plan = OsStr::new(PLAN);
		recheck_fixed(parent, owner, mount, self.owner())?;
		recheck_fixed(parent, plan, mount, self.plan())?;
		self.journal.recheck(parent, mount)?;
		self.receipt.recheck(parent, mount)?;
		self.lease.recheck()
	}
}

struct FixedChild {
	directory_name: &'static str,
	record_name: &'static str,
	directory: Option<PrivateDirectory>,
	record: Option<RecoveryFile>,
}

impl FixedChild {
	fn open(
		parent: &File,
		directory_name: &'static str,
		record_name: &'static str,
		mount: u64,
	) -> Result<Self, StageError> {
		let directory = PrivateDirectory::open(parent, OsStr::new(directory_name), mount)?;
		let record = match &directory {
			Some(dir) => open_checked_record(&dir.file, OsStr::new(record_name), mount)?,
			None => None,
		};
		Ok(Self {
			directory_name,
			record_name,
			directory,
			record,
		})
	}

	fn recheck(&self, parent: &File, mount: u64) -> Result<(), StageError> {
		let parent_name = OsStr::new(self.directory_name);
		match &self.directory {
			Some(directory) => {
				directory.recheck(parent, parent_name, mount)?;
				recheck_fixed(
					&directory.file,
					OsStr::new(self.record_name),
					mount,
					self.record.as_ref(),
				)?;
				directory.recheck(parent, parent_name, mount)
			}
			None => check_absent(parent, parent_name),
		}
	}
}

fn recheck_fixed(
	parent: &File,
	name: &OsStr,
	mount: u64,
	record: Option<&RecoveryFile>,
) -> Result<(), StageError> {
	recheck_regular(parent, name, mount, FilePolicy::Record, record)?;
	if let Some(record) = record {
		record.check_logical_eof().map_err(StageError::ReadBack)?;
		record.recheck_observation().map_err(StageError::ReadBack)?;
	}
	recheck_regular(parent, name, mount, FilePolicy::Record, record)
}

#[cfg(test)]
mod tests;
