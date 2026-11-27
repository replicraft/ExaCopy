use exacopy_endpoint::UnixComponent;
use exacopy_journal::JournalJobId;
use exacopy_journal::remote_download::checkpoints::RemotePrefixHistory;
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_journal::remote_download::{
	MAX_REMOTE_CHECKPOINT_BYTES, RemoteDownloadOwnerRecord, RemoteDownloadScope,
};
use exacopy_platform::linux::{
	DestinationRoot, RecoveryFile, RecoveryInventory, RecoveryWriteLease,
};

use crate::profile::LocalProfile;

use super::super::admission::OwnerDialect;
use super::super::lease::{check_record, check_root, read_owner};
use super::super::{Error, component, job_name, record_identity};
use super::CheckedResumeStartup;

/// Exact original V1 observations reacquired under exclusive witnessed startup custody.
pub(in crate::assembly::linux) struct HeldWitnessStartup<'root, 'donor> {
	donor: RecoveryInventory<'donor>,
	pub(in crate::assembly::linux) lease: RecoveryWriteLease<'root>,
	pub(in crate::assembly::linux) owner: RemoteDownloadOwnerRecord,
	pub(in crate::assembly::linux) owner_file: RecoveryFile,
	pub(in crate::assembly::linux) segment: RecoveryFile,
	pub(in crate::assembly::linux) boundary: RemoteReplayBoundary,
	pub(in crate::assembly::linux) dialect: OwnerDialect,
}

/// Exact shared startup selection held through authenticated carrier establishment.
pub(crate) struct CheckedOriginalWitnessStartup<'held> {
	startup: CheckedResumeStartup<'held>,
	target: Box<[u8]>,
	donor: RecoveryInventory<'held>,
}

impl<'held> CheckedResumeStartup<'held> {
	pub(in crate::assembly::linux) fn hold_witnessed_donor(
		self,
		target: UnixComponent<'_>,
		history: &RemotePrefixHistory<'_>,
	) -> Result<CheckedOriginalWitnessStartup<'held>, Error> {
		if self.history.boundary() != history.boundary() {
			return Err(Error::Binding);
		}
		let prepared = history.prepared();
		let stage = component(history.name())?;
		let donor = self.lease.job().inventory(stage, target)?;
		let file = donor.stage().ok_or(Error::Binding)?;
		if donor.target().is_some()
			|| donor.stage_directory_identity().map(record_identity) != Some(prepared.directory)
			|| record_identity(file.identity()) != prepared.file
		{
			return Err(Error::Binding);
		}
		check_positive_tail_extent(
			file.len(),
			history.covered_extent(),
			history.source().length().get(),
			history.maximum_extent().get(),
		)?;
		donor.recheck()?;
		Ok(CheckedOriginalWitnessStartup {
			startup: self,
			target: target.as_bytes().into(),
			donor,
		})
	}
}

impl<'held> CheckedOriginalWitnessStartup<'held> {
	/// Rechecks the shared startup observations immediately before opening a carrier.
	pub(crate) fn recheck(&self) -> Result<(), Error> {
		let job = self.startup.lease.job();
		let history = &self.startup.history;
		history.check_job(job)?;
		self.donor.recheck()?;
		let owner = job.open_owner()?;
		history.check_owner(&owner)?;
		owner.check_logical_eof()?;
		let segment = job.open_first_segment()?;
		history.check_segment(&segment)?;
		segment.check_logical_eof()?;
		history.check_job(job)
	}

	/// Releases only the cooperative read lock and matches the original pinned records.
	pub(in crate::assembly::linux) fn open_witnessed<'root>(
		self,
		root: &'root DestinationRoot,
		profile: &LocalProfile,
		job: JournalJobId,
		scope: &RemoteDownloadScope,
	) -> Result<HeldWitnessStartup<'root, 'held>, Error> {
		if self.target.as_ref() != scope.destination.target() {
			return Err(Error::Binding);
		}
		let name = job_name(job);
		check_root(root, profile, scope, name.as_bytes())?;
		let name = component(name.as_bytes())?;
		let dialect = OwnerDialect::select(scope.source.route(), scope.source.path_root())?;
		self.recheck()?;
		let history = self.startup.release_for_exclusive();
		let observed = root.open_recovery_job(name)?;
		history.check_job(&observed)?;
		let lease = root.try_recovery_write_lease(name, observed.identity())?;
		let reopened = lease.job();
		history.check_job(reopened)?;
		let owner_file = reopened.open_owner()?;
		history.check_owner(&owner_file)?;
		let owner = read_owner(&owner_file, profile, dialect)?;
		let manifest = owner.manifest();
		if manifest.job != job
			|| manifest.job_directory != record_identity(reopened.identity())
			|| &manifest.scope != scope
		{
			return Err(Error::Binding);
		}
		let segment = reopened.open_first_segment()?;
		history.check_segment(&segment)?;
		let boundary = history.boundary();
		let held = HeldWitnessStartup {
			donor: self.donor,
			lease,
			owner,
			owner_file,
			segment,
			boundary,
			dialect,
		};
		held.open_segment()?;
		Ok(held)
	}
}

impl HeldWitnessStartup<'_, '_> {
	/// Confirms the original pinned donor and reopened inventory before reading.
	pub(in crate::assembly::linux) fn check_donor(
		&self,
		current: &RecoveryInventory<'_>,
	) -> Result<(), Error> {
		self.donor.recheck()?;
		current.recheck()?;
		if current.target().is_some()
			|| self.donor.target().is_some()
			|| current.stage_directory_identity() != self.donor.stage_directory_identity()
		{
			return Err(Error::Binding);
		}
		check_record(
			self.donor.stage().ok_or(Error::Binding)?,
			current.stage().ok_or(Error::Binding)?,
		)?;
		self.donor.recheck()?;
		current.recheck()?;
		Ok(())
	}

	/// Opens an exact byte-zero replay aperture and checks the original held records.
	pub(in crate::assembly::linux) fn open_segment(&self) -> Result<RecoveryFile, Error> {
		let job = self.lease.job();
		let owner = job.open_owner()?;
		check_record(&self.owner_file, &owner)?;
		let segment = job.open_first_segment()?;
		check_record(&self.segment, &segment)?;
		if segment.len() != self.boundary.offset {
			return Err(Error::Binding);
		}
		segment.check_logical_eof()?;
		job.recheck()?;
		Ok(segment)
	}
}

fn check_positive_tail_extent(
	extent: u64,
	covered: u64,
	prior_source: u64,
	maximum: u64,
) -> Result<(), Error> {
	let uncheckpointed = extent.checked_sub(covered).ok_or(Error::Binding)?;
	if uncheckpointed > MAX_REMOTE_CHECKPOINT_BYTES || extent > prior_source || extent >= maximum {
		return Err(Error::Binding);
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn witnessed_donor_extent_keeps_one_window_and_room_for_a_positive_tail() {
		let covered = 7;
		let one_window = covered + MAX_REMOTE_CHECKPOINT_BYTES;
		let prior_source = one_window + 1;
		let maximum = prior_source + 1;
		assert!(check_positive_tail_extent(covered, covered, prior_source, maximum).is_ok());
		assert!(check_positive_tail_extent(one_window, covered, prior_source, maximum).is_ok());
		assert!(check_positive_tail_extent(prior_source, covered, prior_source, maximum).is_err());
		assert!(check_positive_tail_extent(covered - 1, covered, prior_source, maximum).is_err());
		assert!(check_positive_tail_extent(covered + 1, covered, covered, maximum).is_err());
		assert!(check_positive_tail_extent(one_window, covered, one_window, one_window).is_err());
		// A previous source observation cannot bound the new live source.
		assert!(check_positive_tail_extent(one_window, covered, one_window, maximum).is_ok());
	}
}
