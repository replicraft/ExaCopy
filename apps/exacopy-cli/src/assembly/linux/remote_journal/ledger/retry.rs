use std::num::NonZeroU64;

use exacopy_endpoint::UnixComponent;

use exacopy_journal::remote_download::RemoteSourceObservation;

use super::super::RetryCaptureStamp;
use super::super::lease::{CheckedCandidate, check_record, retry::FreshRetryAllocation};
use super::{Attempt, Error, RemoteJobJournal, component, context};

impl<'lease> RemoteJobJournal<'lease> {
	pub(in crate::assembly::linux) fn allocate_retry<'stage>(
		&mut self,
		candidate: &'stage CheckedCandidate<'stage>,
		preview: &FreshRetryAllocation,
		observed: RemoteSourceObservation,
	) -> Result<super::AllocatedStage<'stage>, Error>
	where
		'lease: 'stage,
	{
		let previous = self.spent.last().map(|attempt| attempt.epochs);
		let (boundary, nonce, epochs, source) = preview.parts();
		if self.active.is_some()
			|| self.boundary != boundary
			|| candidate.name.as_bytes() != preview.name()
			|| observed != source
			|| super::next_epochs(previous, epochs.source)? != epochs
		{
			return Err(Error::Binding);
		}
		self.allocate(candidate, epochs.source, observed, nonce)
	}

	pub(in crate::assembly::linux) fn stamp_failed_read(
		&self,
		name: UnixComponent<'_>,
		source_epoch: NonZeroU64,
		extent: u64,
	) -> Result<RetryCaptureStamp, Error> {
		self.activation.recheck()?;
		let Some(Attempt::Prepared(active)) = &self.active else {
			return Err(Error::Binding);
		};
		let last = self.spent.last().ok_or(Error::Binding)?;
		if active.allocation.epochs.source != source_epoch
			|| last.epochs != active.allocation.epochs
			|| last.nonce != active.allocation.nonce
			|| name.as_bytes() != last.name.as_ref()
			|| extent < active.covered
			|| extent >= active.allocation.source.length().get()
		{
			return Err(Error::Binding);
		}
		let segment = self.checked_current()?;
		let job = self.lease.job();
		let owner = job.open_owner()?;
		check_record(self.owner_file, &owner)?;
		let target = component(self.owner.manifest().scope.destination.target())?;
		let inventory = job.inventory(name, target)?;
		if inventory.target().is_some() {
			return Err(Error::Conflict);
		}
		let stage = inventory.stage().ok_or(Error::UnknownStage)?;
		if inventory.stage_directory_identity() != Some(self.directory)
			|| stage.identity() != active.file
			|| stage.len() != extent
		{
			return Err(Error::UnknownStage);
		}
		stage.check_logical_eof()?;
		let anchor = self.lease.pin_stopped_stage(inventory)?;
		owner.recheck_observation()?;
		segment.recheck_observation()?;
		self.activation.recheck()?;
		Ok(RetryCaptureStamp {
			context: context(self.owner),
			owner,
			segment,
			boundary: self.boundary,
			allocation: active.allocation.head,
			prepared: active.head,
			epochs: active.allocation.epochs,
			source: active.allocation.source,
			name: last.name.clone(),
			directory: self.directory,
			file: active.file,
			extent,
			grant: self.activation.grant_digest,
			qualification: self.activation.qualification_digest,
			anchor,
		})
	}
}
