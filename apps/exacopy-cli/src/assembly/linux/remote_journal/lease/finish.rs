use std::io::Read as _;
use std::num::NonZeroU64;

use exacopy_journal::MAX_FIRST_SEGMENT_BYTES;
use exacopy_journal::frame::{ChainHead, Frame, FrameKind, FrameReader};
use exacopy_journal::remote_download::finalization_replay::{
	RemoteFinalizationPhase, RemoteFinalizationReplay, RemoteReceiptAssociation,
	replay_remote_finalization,
};
use exacopy_journal::remote_download::{RemoteDownloadContext, RemoteDownloadOwnerRecord};
use exacopy_transfer::remote_finalization::CommittedRemoteReceipt;

use super::super::receipt::{HeldReceiptWorkspace, read_receipt};
use super::{CheckedCandidate, Error, RemoteJobJournal, RemoteJobLease, context};

pub(in crate::assembly::linux) struct FinalizationHistory<'owner> {
	pub(in crate::assembly::linux) owner: &'owner RemoteDownloadOwnerRecord,
	pub(in crate::assembly::linux) replay: RemoteFinalizationReplay<'owner>,
	pub(in crate::assembly::linux) allocation: Frame,
	pub(in crate::assembly::linux) prepared: Frame,
}

impl RemoteJobLease<'_> {
	pub(in crate::assembly::linux) fn open_fresh_capture(
		&self,
		candidate: &CheckedCandidate<'_>,
	) -> Result<RemoteJobJournal<'_>, Error> {
		use RemoteFinalizationPhase as Phase;
		match self.phase {
			Phase::Capture | Phase::Retired => self.open_writer(candidate),
			Phase::Sealed | Phase::Verified | Phase::MetadataReady => {
				self.retire_and_open_writer(candidate)
			}
			_ => Err(Error::Lifecycle {
				phase: self.phase,
				boundary: self.boundary,
				issue: None,
			}),
		}
	}

	pub(in crate::assembly::linux) fn next_source_epoch(&self) -> Result<NonZeroU64, Error> {
		match self.last_source_epoch {
			Some(epoch) => epoch.checked_add(1).ok_or(Error::Attempt),
			None => Ok(NonZeroU64::MIN),
		}
	}

	pub(in crate::assembly::linux) fn context(&self) -> RemoteDownloadContext {
		context(&self.owner)
	}

	pub(in crate::assembly::linux) fn receipts(&self) -> HeldReceiptWorkspace<'_> {
		HeldReceiptWorkspace(&self.lease)
	}

	pub(in crate::assembly::linux) fn finalization_history(
		&self,
		journal: &RemoteJobJournal<'_>,
	) -> Result<FinalizationHistory<'_>, Error> {
		if !journal.held_by(&self.lease) {
			return Err(Error::Binding);
		}
		let expected = journal.confirmed_boundary();
		let mut segment = journal.checked_current()?;
		let replay = self.scan(&mut segment)?;
		if replay.issue().is_some()
			|| replay.phase() != RemoteFinalizationPhase::Capture
			|| replay.boundary() != expected
			|| expected.offset > MAX_FIRST_SEGMENT_BYTES
		{
			return Err(Error::Binding);
		}
		let attempt = replay.attempts().last().ok_or(Error::Binding)?;
		let allocation_head = attempt.allocation();
		let prepared_head = attempt.prepared().ok_or(Error::Binding)?.head;

		let mut current = journal.checked_current()?;
		let selected = (&mut current).take(expected.offset);
		let mut frames = FrameReader::new(selected, ChainHead::start());
		let mut allocation = None;
		let mut prepared = None;
		while let Some(frame) = frames.next_frame()? {
			if frame.head() == allocation_head && frame.kind() == FrameKind::RemoteStageAllocated {
				allocation = Some(frame);
			} else if frame.head() == prepared_head && frame.kind() == FrameKind::EntryPrepared {
				prepared = Some(frame);
			}
		}
		if frames.head() != expected.head || frames.offset() != expected.offset {
			return Err(Error::Binding);
		}
		current.check_logical_eof()?;
		current.recheck_observation()?;
		segment.recheck_observation()?;
		Ok(FinalizationHistory {
			owner: &self.owner,
			replay,
			allocation: allocation.ok_or(Error::Binding)?,
			prepared: prepared.ok_or(Error::Binding)?,
		})
	}

	pub(in crate::assembly::linux) fn check_committed_receipt(
		&self,
		journal: &RemoteJobJournal<'_>,
		result: &CommittedRemoteReceipt,
	) -> Result<(), Error> {
		if !journal.held_by(&self.lease) {
			return Err(Error::Binding);
		}
		let bytes = read_receipt(self.job())?;
		let mut segment = journal.checked_current()?;
		let trust =
			self.activation
				.dialect
				.trust(&self.owner, self.owner.manifest().profile, &self.key)?;
		let replay = replay_remote_finalization(
			&mut segment,
			&trust,
			self.activation.qualification_digest,
			Some(&bytes),
		)?;
		if replay.issue().is_some()
			|| replay.phase() != RemoteFinalizationPhase::ReceiptCommitted
			|| replay.receipt_association() != RemoteReceiptAssociation::Matched
			|| replay.boundary() != journal.confirmed_boundary()
			|| replay.boundary().head != result.commitment
			|| replay.committed_digest() != Some(result.digest)
			|| bytes != result.canonical_receipt
		{
			return Err(Error::Binding);
		}
		segment.check_logical_eof()?;
		segment.recheck_observation()?;
		self.job().recheck()?;
		Ok(())
	}
}
