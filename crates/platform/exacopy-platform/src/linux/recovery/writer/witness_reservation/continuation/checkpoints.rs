use exacopy_model::retained_prefix::Head;

use crate::linux::{RetainedSuffixWriter, SyncedSuffixRange};

use super::{
	ActiveWitnessReservation, ContinuationReservationError, MAX_ENCODED_CONTINUATION,
	ReservedContinuationRequest, ReservedJournalRead, StageError,
	WitnessReservationObservationError, append_held, observe_successor,
};

impl ActiveWitnessReservation<'_> {
	/// Stops all subsequent appends through this active reservation.
	pub fn stop(&mut self) {
		self.healthy = false;
	}

	/// Checks the exact held writer association and unchanged active journal/receipt.
	///
	/// # Errors
	/// Refuses a retired reservation, unrelated writer or changed custody.
	pub fn check_capture_writer(
		&self,
		writer: &RetainedSuffixWriter<'_, '_>,
	) -> Result<(), WitnessReservationObservationError> {
		if !self.healthy || !writer.matches_reader(self.reservation.held.stage) {
			return Err(StageError::IdentityChanged.into());
		}
		self.check_active()
	}

	/// Checks active journal custody without reusing the old adopted stage stamp.
	///
	/// The data writer owns the evolving stage observations and checks them at
	/// each effect boundary.
	///
	/// # Errors
	/// Refuses retired or changed authorization/namespace/file observations.
	pub fn check_active(&self) -> Result<(), WitnessReservationObservationError> {
		self.check_active_journal()?;
		self.reservation.receipt.recheck(&self.reservation.held)?;
		Ok(())
	}

	pub(super) fn check_active_journal(&self) -> Result<(), WitnessReservationObservationError> {
		if !self.healthy {
			return Err(StageError::PriorBarrierFailure.into());
		}
		let reservation = &self.reservation;
		let held = &reservation.held;
		held.eligibility.recheck_for(held.lease.job().root)?;
		reservation
			.journal
			.recheck(held.lease, &reservation.readback)?;
		Ok(())
	}

	/// Appends the exact continued checkpoint to the same reserved journal.
	///
	/// The application builds and checks the canonical frame against its source range,
	/// continuation lineage and current accepted head. The file barrier proof keeps
	/// the original stage writer parked until the actual checkpoint is independently
	/// reread; the application may then confirm that exact checkpoint on the writer.
	///
	/// # Errors
	/// Refuses changed state or exhausted capacity, incorrect range/order, rejected
	/// history/admission, and failed writes, barriers or independent replay. A
	/// failed operation retires this active journal. Submitted evidence remains.
	pub fn append_checkpoint<G, E>(
		&mut self,
		barrier: &SyncedSuffixRange<'_, '_, '_>,
		successor: Head,
		encoded_frame: &[u8],
		verify_prior: impl FnOnce(ReservedJournalRead<'_>) -> Result<(), E>,
		enter: impl FnOnce(ReservedContinuationRequest<'_>) -> Result<G, E>,
		verify_successor: impl FnOnce(ReservedJournalRead<'_>) -> Result<(), E>,
	) -> Result<(), ContinuationReservationError<E>> {
		use ContinuationReservationError as Error;

		if !std::mem::replace(&mut self.healthy, false) {
			return Err(Error::Preflight(StageError::PriorBarrierFailure.into()));
		}
		let previous = self.head;
		let range = barrier.range();
		let first = self.reservation.plan.accepted();
		let last = first.sequence + self.reservation.plan.reserve_frames().get();
		let length = u64::try_from(encoded_frame.len()).map_err(|_| Error::Bounds)?;
		if self.confirmed_checkpoint_end != range.start
			|| range.start >= range.end
			|| encoded_frame.is_empty()
			|| encoded_frame.len() > MAX_ENCODED_CONTINUATION
			|| previous.end.checked_add(length) != Some(successor.end)
			|| previous.sequence.checked_add(1) != Some(successor.sequence)
			|| successor.digest == [0; 32]
			|| successor.digest == previous.digest
			|| successor.end >= self.reservation.plan.reserve_end()
			|| successor.sequence >= last
		{
			return Err(Error::Bounds);
		}
		self.check_checkpoint(barrier).map_err(Error::Preflight)?;
		verify_prior(self.reservation.read_aperture()).map_err(Error::PriorReplay)?;
		self.check_checkpoint(barrier).map_err(Error::Preflight)?;
		let request = self.reservation.continuation_request(previous, successor);
		let guard = enter(request).map_err(Error::Admission)?;
		append_held(&mut self.reservation.journal, encoded_frame, guard)
			.map_err(Error::Submitted)?;
		let readback = observe_successor(
			&self.reservation.journal,
			self.reservation.held.lease,
			&self.reservation.readback,
			previous.end,
			successor.end,
			encoded_frame,
		)
		.map_err(Error::Readback)?;
		self.reservation.readback = readback;
		verify_successor(self.reservation.read_aperture()).map_err(Error::SuccessorReplay)?;
		self.check_checkpoint(barrier).map_err(Error::Readback)?;
		self.head = successor;
		self.confirmed_checkpoint_end = range.end;
		self.healthy = true;
		Ok(())
	}

	fn check_checkpoint(
		&self,
		barrier: &SyncedSuffixRange<'_, '_, '_>,
	) -> Result<(), WitnessReservationObservationError> {
		let reservation = &self.reservation;
		let held = &reservation.held;
		held.eligibility.recheck_for(held.lease.job().root)?;
		barrier.check_for(held.stage)?;
		reservation.receipt.recheck(held)?;
		reservation
			.journal
			.recheck(held.lease, &reservation.readback)?;
		Ok(())
	}
}
