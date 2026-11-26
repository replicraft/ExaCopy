use std::cell::Cell;

use exacopy_journal::SyncedFrame;
use exacopy_journal::frame::{ChainHead, Frame, FrameKind};
use exacopy_journal::remote_download::finalization::{
	MAX_REMOTE_FINALIZATION_BYTES, RemoteDownloadReceipt, RemoteFinalizationBinding,
	RemoteFinalizationBody, RemoteFinalizationRecord, RemotePublicationObservation,
};
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;
use exacopy_platform::linux::{RecoveryFile, RecoveryWriteLease};
use exacopy_transfer::remote_finalization::{RemoteFinalizationJournal, RemotePublicationFence};

use super::super::receipt::read_receipt;
use super::{
	Error, RemoteJobJournal, append::append_payload_admitted, check_current, component, context,
	readback_frame, record_identity,
};

#[derive(Default)]
pub(in crate::assembly::linux) struct IntentReadback(
	Cell<Option<(RemoteFinalizationBinding, ChainHead)>>,
);

impl IntentReadback {
	pub(in crate::assembly::linux) fn consume(
		&self,
		fence: RemotePublicationFence,
	) -> Result<RemoteFinalizationBinding, Error> {
		let (binding, head) = self.0.take().ok_or(Error::Binding)?;
		if binding.context != fence.context() || head != fence.intent() {
			return Err(Error::Binding);
		}
		Ok(binding)
	}
}

pub(in crate::assembly::linux) struct FinalizationJournal<'run, 'lease> {
	journal: &'run mut RemoteJobJournal<'lease>,
	intent: &'run IntentReadback,
	binding: RemoteFinalizationBinding,
	next: Option<FrameKind>,
}

impl<'lease> RemoteJobJournal<'lease> {
	pub(in crate::assembly::linux) fn finalization<'run>(
		&'run mut self,
		intent: &'run IntentReadback,
	) -> Result<FinalizationJournal<'run, 'lease>, Error> {
		if intent.0.get().is_some() {
			return Err(Error::Binding);
		}
		let Some(super::Attempt::Prepared(active)) = &self.active else {
			return Err(Error::Binding);
		};
		let binding = RemoteFinalizationBinding {
			context: context(self.owner),
			prepared: active.head,
			epochs: active.allocation.epochs,
			stage: record_identity(active.file),
		};
		self.checked_current()?;
		Ok(FinalizationJournal {
			journal: self,
			intent,
			binding,
			next: Some(FrameKind::StageSealed),
		})
	}

	pub(in crate::assembly::linux) fn confirmed_boundary(&self) -> RemoteReplayBoundary {
		self.boundary
	}

	pub(in crate::assembly::linux) fn held_by(&self, expected: &RecoveryWriteLease<'_>) -> bool {
		std::ptr::eq(self.lease, expected)
	}

	pub(in crate::assembly::linux) fn checked_current(&self) -> Result<RecoveryFile, Error> {
		if self.writer.is_none() {
			return Err(Error::Stopped);
		}
		self.segment.recheck_observation()?;
		let current = check_current(
			self.lease.job(),
			self.owner_file,
			self.segment.identity(),
			self.boundary.offset,
		)?;
		current.check_logical_eof()?;
		current.recheck_observation()?;
		Ok(current)
	}
}

impl RemoteFinalizationJournal for FinalizationJournal<'_, '_> {
	type Error = Error;

	fn boundary(&mut self) -> Result<RemoteReplayBoundary, Self::Error> {
		if let Err(cause) = self.journal.checked_current() {
			self.journal.writer = None;
			return Err(cause);
		}
		Ok(self.journal.boundary)
	}

	fn append(
		&mut self,
		expected: RemoteReplayBoundary,
		kind: FrameKind,
		payload: Vec<u8>,
	) -> Result<(Frame, SyncedFrame), Self::Error> {
		use RemoteFinalizationBody as Body;
		if self.boundary()? != expected || self.next != Some(kind) {
			return Err(Error::Binding);
		}
		let record = RemoteFinalizationRecord::decode(&payload)?;
		if record.binding() != self.binding
			|| record.predecessor() != expected.head
			|| record.body().kind() != kind
		{
			return Err(Error::Binding);
		}
		let next = match record.body() {
			Body::StageSealed { .. } => Some(FrameKind::VerificationRecorded),
			Body::VerificationRecorded { .. } => Some(FrameKind::MetadataRecorded),
			Body::MetadataRecorded(_) => Some(FrameKind::PublishIntent),
			Body::PublishIntent {
				target,
				directory,
				qualification,
				..
			} => {
				let active = self.journal.activation;
				active.recheck()?;
				if target.root != active.scope.destination.root()
					|| target.parent != active.publication_authority().parent
					|| target.component != component(active.scope.destination.target())?
					|| directory != record_identity(self.journal.directory)
					|| qualification != active.qualification_digest
				{
					return Err(Error::Binding);
				}
				Some(FrameKind::PublishObserved)
			}
			Body::PublishObserved(RemotePublicationObservation::Published(_)) => {
				Some(FrameKind::DurabilityRecorded)
			}
			Body::PublishObserved(_) => None,
			Body::DurabilityRecorded { .. } => Some(FrameKind::ReceiptCommitted),
			Body::ReceiptCommitted { digest } => {
				let bytes = read_receipt(self.journal.lease.job())?;
				let receipt = RemoteDownloadReceipt::decode(&bytes)?;
				if receipt.digest()? != digest
					|| receipt.binding() != self.binding
					|| receipt.scope() != self.journal.activation.publication_authority().scope
					|| receipt.durability() != expected.head
				{
					return Err(Error::Binding);
				}
				None
			}
		};
		let mut writer = self.journal.writer.take().ok_or(Error::Stopped)?;

		let (appended, synced, boundary) =
			append_payload_admitted(&mut writer, expected, kind, payload, || match kind {
				FrameKind::StageSealed
				| FrameKind::VerificationRecorded
				| FrameKind::MetadataRecorded
				| FrameKind::PublishIntent => self
					.journal
					.activation
					.enter_effect()
					.map(Some)
					.map_err(std::io::Error::other),
				_ => Ok(None),
			})?;
		let current = check_current(
			self.journal.lease.job(),
			self.journal.owner_file,
			self.journal.segment.identity(),
			boundary.offset,
		)?;
		let actual = readback_frame(&current, expected, boundary, MAX_REMOTE_FINALIZATION_BYTES)?;
		if appended != actual
			|| RemoteFinalizationRecord::from_frame(&actual)?.binding() != self.binding
		{
			return Err(Error::Binding);
		}
		self.journal.segment = current;
		self.journal.boundary = boundary;
		self.journal.writer = Some(writer);
		self.next = next;
		if kind == FrameKind::PublishIntent {
			self.intent.0.set(Some((self.binding, actual.head())));
		}
		Ok((actual, synced))
	}
}
