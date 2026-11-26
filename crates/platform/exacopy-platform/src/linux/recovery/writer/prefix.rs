use std::cell::Cell;
use std::os::unix::ffi::OsStrExt as _;
use std::sync::MutexGuard;

use exacopy_endpoint::linux_job::JobFileIdentity;
use exacopy_endpoint::{ReadView, UnixComponent};

use super::{RecoveryFile, RecoveryInventory, RecoveryWriteLease, StageError};
use crate::linux::stage::{FILE_MODE, check_no_visible_attributes};

mod suffix;
#[cfg(test)]
mod tests;

pub use suffix::{
	RetainedSuffixReadback, RetainedSuffixWriter, SuffixEffect, SuffixError, SyncedRetainedPrefix,
	SyncedSuffixRange,
};

/// Expected names and identities from the selected prepared-stage history.
///
/// These comparisons bind a read-only observation. The caller must independently
/// authenticate the history and confirm it describes this job and selected target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedPrefixSelection<'name> {
	/// The exact private basename recorded in the accepted preparation.
	pub stage: UnixComponent<'name>,
	/// The exact public basename selected by the caller.
	pub target: UnixComponent<'name>,
	/// The observed native identity expected for the private stage directory.
	pub directory: JobFileIdentity,
	/// The observed native identity expected for the private stage file.
	pub file: JobFileIdentity,
}

impl RecoveryWriteLease<'_> {
	/// Pins the exact retained stage and absent target for read-only prefix checks.
	///
	/// The inventory must come from this lease and retain the original read-only
	/// observation. This capability keeps other stage access excluded through
	/// the lease, even while the caller compares the held view with another source.
	/// # Errors
	/// Refuses a changed or foreign inventory, an occupied target, mismatched
	/// names or identities, unsafe metadata, or another active stage capability.
	pub fn read_retained_prefix<'lease>(
		&'lease self,
		inventory: &'lease RecoveryInventory<'lease>,
		expected: RetainedPrefixSelection<'_>,
	) -> Result<RetainedPrefixRead<'lease>, StageError> {
		if !std::ptr::eq(inventory.job, self.job()) || inventory.target().is_some() {
			return Err(StageError::IdentityChanged);
		}
		let stage = inventory.stage().ok_or(StageError::IdentityChanged)?;
		let directory = inventory
			.stage_directory_identity()
			.ok_or(StageError::IdentityChanged)?;
		let actual = RetainedPrefixSelection {
			stage: inventory_component(&inventory.stage_name)?,
			target: inventory_component(&inventory.target_name)?,
			directory: directory.into(),
			file: stage.identity().into(),
		};
		if actual != expected {
			return Err(StageError::IdentityChanged);
		}
		let reader = RetainedPrefixRead {
			_access: self.try_stage_access()?,
			lease: self,
			inventory,
			stage,
			selection: actual,
			suffix_spent: Cell::new(false),
		};
		reader.recheck_observation()?;
		Ok(reader)
	}
}

fn inventory_component(name: &std::ffi::OsStr) -> Result<UnixComponent<'_>, StageError> {
	UnixComponent::new(name.as_bytes()).map_err(|_| StageError::IdentityChanged)
}

/// One read-only view of the exact retained ordinary stage under a job write lease.
///
/// This view does not establish byte equality with a source or journal validity.
/// The caller rechecks it around comparisons and keeps the same view for any
/// later decision that depends on the original native observation.
#[derive(Debug)]
#[must_use]
pub struct RetainedPrefixRead<'lease> {
	_access: MutexGuard<'lease, ()>,
	lease: &'lease RecoveryWriteLease<'lease>,
	inventory: &'lease RecoveryInventory<'lease>,
	stage: &'lease RecoveryFile,
	selection: RetainedPrefixSelection<'lease>,
	suffix_spent: Cell<bool>,
}

impl RetainedPrefixRead<'_> {
	pub(super) fn recheck_for_lease(
		&self,
		lease: &RecoveryWriteLease<'_>,
	) -> Result<(), StageError> {
		if !std::ptr::eq(self.inventory.job, lease.job()) {
			return Err(StageError::IdentityChanged);
		}
		self.recheck_observation()
	}

	/// Returns the names and native identities matched to this exact view.
	#[must_use]
	pub const fn selection(&self) -> RetainedPrefixSelection<'_> {
		self.selection
	}
}

impl ReadView for RetainedPrefixRead<'_> {
	type Error = StageError;

	fn length(&self) -> u64 {
		self.stage.len()
	}

	fn recheck_observation(&self) -> Result<(), Self::Error> {
		if self.stage.observation().mode() != FILE_MODE.as_raw_mode() {
			return Err(StageError::UnsafeFile);
		}
		self.inventory.recheck()?;
		check_no_visible_attributes(&self.stage.file)?;
		ReadView::recheck_observation(self.stage).map_err(StageError::ReadBack)?;
		self.inventory.recheck()
	}

	fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
		self.stage
			.read_exact_at(offset, bytes)
			.map_err(StageError::ReadBack)
	}
}
