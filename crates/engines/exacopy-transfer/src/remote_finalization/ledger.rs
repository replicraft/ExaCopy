use std::io;

use exacopy_endpoint::JournalFileBarrier;
use exacopy_journal::SyncedFrame;
use exacopy_journal::frame::{FRAME_OVERHEAD_BYTES, Frame, FrameWriter};
use exacopy_journal::remote_download::finalization::{
	RemoteFinalizationBinding, RemoteFinalizationBody, RemoteFinalizationRecord,
};
use exacopy_journal::remote_download::replay::RemoteReplayBoundary;

use super::{
	FinalizationCause, FinalizationFailure, FinalizationProgress, RemoteFinalizationJournal,
};

type AppendResult<J, A, S, R> = Result<(Frame, SyncedFrame), FinalizationFailure<J, A, S, R>>;

pub(super) struct Ledger<'writer, J> {
	journal: &'writer mut J,
	pub boundary: RemoteReplayBoundary,
	binding: RemoteFinalizationBinding,
	pub progress: FinalizationProgress,
}

impl<'writer, J: RemoteFinalizationJournal> Ledger<'writer, J> {
	pub fn new(
		journal: &'writer mut J,
		boundary: RemoteReplayBoundary,
		binding: RemoteFinalizationBinding,
	) -> Self {
		Self {
			journal,
			boundary,
			binding,
			progress: FinalizationProgress::BeforeIntent,
		}
	}

	pub fn fail<A, S, R>(
		&self,
		cause: FinalizationCause<J::Error, A, S, R>,
	) -> FinalizationFailure<J::Error, A, S, R> {
		FinalizationFailure {
			progress: self.progress,
			head: self.boundary.head,
			cause,
		}
	}

	pub fn check<A, S, R>(&mut self) -> Result<(), FinalizationFailure<J::Error, A, S, R>> {
		let current = self
			.journal
			.boundary()
			.map_err(|cause| self.append_failed(FinalizationCause::JournalBoundary(cause)))?;
		if current != self.boundary {
			return Err(self.append_failed(FinalizationCause::Binding));
		}
		Ok(())
	}

	pub fn append<A, S, R>(
		&mut self,
		body: RemoteFinalizationBody<'_>,
	) -> AppendResult<J::Error, A, S, R> {
		let kind = body.kind();
		let canonical = RemoteFinalizationRecord::new(self.binding, self.boundary.head, body)
			.and_then(|record| record.encode())
			.map_err(|cause| self.fail(FinalizationCause::Format(cause)))?;
		let mut framer = FrameWriter::new(io::sink(), self.boundary.head);
		let expected_head = framer
			.append(kind, &canonical)
			.map_err(|_| self.fail(FinalizationCause::Capacity))?;
		let stride = u64::try_from(canonical.len() + FRAME_OVERHEAD_BYTES)
			.map_err(|_| self.fail(FinalizationCause::Capacity))?;
		let offset = self
			.boundary
			.offset
			.checked_add(stride)
			.ok_or_else(|| self.fail(FinalizationCause::Capacity))?;
		self.check()?;
		let (frame, synced) = self
			.journal
			.append(self.boundary, kind, canonical.clone())
			.map_err(|cause| self.append_failed(FinalizationCause::Journal { kind, cause }))?;
		if frame.kind() != kind
			|| synced.kind() != kind
			|| synced.barrier() != JournalFileBarrier::SyncAll
			|| frame.head() != expected_head
			|| synced.head() != expected_head
			|| frame.previous_digest() != self.boundary.head.digest()
			|| frame.payload() != canonical
		{
			return Err(self.append_failed(FinalizationCause::JournalAcknowledgement(kind)));
		}
		let expected = RemoteReplayBoundary {
			head: expected_head,
			offset,
		};
		let current = self
			.journal
			.boundary()
			.map_err(|cause| self.append_failed(FinalizationCause::JournalBoundary(cause)))?;
		if current != expected {
			return Err(self.append_failed(FinalizationCause::JournalAcknowledgement(kind)));
		}
		self.boundary = expected;
		Ok((frame, synced))
	}

	fn append_failed<A, S, R>(
		&mut self,
		cause: FinalizationCause<J::Error, A, S, R>,
	) -> FinalizationFailure<J::Error, A, S, R> {
		if matches!(
			self.progress,
			FinalizationProgress::BeforeIntent | FinalizationProgress::SealedBeforeIntent
		) {
			self.progress = FinalizationProgress::PrivateJournalUncertain;
		}
		self.fail(cause)
	}
}
