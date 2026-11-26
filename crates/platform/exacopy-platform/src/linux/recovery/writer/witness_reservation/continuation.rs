use std::io::{self, Write as _};

use exacopy_model::retained_prefix::Head;

use super::{
	FIRST_SEGMENT, HeldFirstSegment, PendingWitnessReservation, PhantomData, RecoveryFile,
	RecoveryWriteLease, ReservedJournalRead, RetainedPrefixSelection, StageError,
	WitnessReservationAuthority, WitnessReservationObservationError, WitnessReservationPlan,
	open_checked_record,
};
use crate::linux::{FileIdentity, SyncedRetainedPrefix};

mod checkpoints;

// The owner codec bounds the payload to 1,024 bytes and framing to 92 bytes.
const MAX_ENCODED_CONTINUATION: usize = 1116;

/// The held objects, original capacity and exact transition presented to the gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReservedContinuationRequest<'name> {
	/// Original independently selected authority commitments.
	pub authority: WitnessReservationAuthority,
	/// Storage owner's original exact whole-pass reservation.
	pub plan: WitnessReservationPlan,
	/// Exact selected next frame boundary.
	pub successor: Head,
	/// Exact current accepted predecessor under the held reservation.
	pub previous: Head,
	/// Same held parent destination.
	pub destination: FileIdentity,
	/// Same held job directory.
	pub job: FileIdentity,
	/// Same original stage and target names and IDs.
	pub stage: RetainedPrefixSelection<'name>,
	/// Same held journal directory.
	pub journal_directory: FileIdentity,
	/// Same held first-segment identity.
	pub segment: FileIdentity,
	/// Same originally allocated anonymous receipt.
	pub receipt: FileIdentity,
}

/// Failure of the guarded transition to an active witnessed reservation.
#[derive(Debug)]
#[non_exhaustive]
pub enum ContinuationReservationError<E> {
	/// Original plan, current physical stage or journal did not match before writing.
	Preflight(WitnessReservationObservationError),
	/// The exact next frame is empty, oversized, or outside the reservation.
	Bounds,
	/// The application's independent old-prefix replay refused before submission.
	PriorReplay(E),
	/// The authority guard refused before submission.
	Admission(E),
	/// The frame's write or full file sync failed after submission began.
	Submitted(io::Error),
	/// Native read-back failed after the frame write was submitted.
	Readback(WitnessReservationObservationError),
	/// The application could not confirm the successor from independent held replay.
	SuccessorReplay(E),
}

/// The completed transition, keeping the original segment, receipt and reader custody.
///
/// Later checkpoint or receipt effects require their own checked methods.
#[must_use]
pub struct ActiveWitnessReservation<'lease> {
	reservation: PendingWitnessReservation<'lease>,
	head: Head,
	confirmed_checkpoint_end: u64,
	healthy: bool,
}

impl<'lease> PendingWitnessReservation<'lease> {
	/// Commits exactly one selected continuation on the original open file.
	///
	/// The trusted application derives the encoded frame through the storage
	/// codec, verifies the complete old prefix, and independently authenticates
	/// the new canonical kind-40 successor from the read-back cursor. The
	/// native guard is held through only this frame and its file barrier.
	///
	/// # Errors
	/// Refuses an unrelated prefix proof, bounds, authority, changed native
	/// identities, write or barrier failures, and failed independent replay.
	/// A failure consumes the reservation. Any submitted bytes stay in place.
	pub fn append_continuation<G, E>(
		mut self,
		prefix: &SyncedRetainedPrefix<'_, '_>,
		successor: Head,
		encoded_frame: &[u8],
		verify_prior: impl FnOnce(ReservedJournalRead<'_>) -> Result<(), E>,
		enter: impl FnOnce(ReservedContinuationRequest<'_>) -> Result<G, E>,
		verify_successor: impl FnOnce(ReservedJournalRead<'_>) -> Result<(), E>,
	) -> Result<ActiveWitnessReservation<'lease>, ContinuationReservationError<E>> {
		use ContinuationReservationError as Error;

		let previous = self.plan.accepted();
		let length = u64::try_from(encoded_frame.len()).map_err(|_| Error::Bounds)?;
		if encoded_frame.is_empty()
			|| encoded_frame.len() > MAX_ENCODED_CONTINUATION
			|| previous.end.checked_add(length) != Some(successor.end)
			|| previous.sequence.checked_add(1) != Some(successor.sequence)
			|| successor.digest == [0; 32]
			|| successor.digest == previous.digest
			|| successor.end >= self.plan.reserve_end()
			|| self.plan.reserve_frames().get() <= 1
		{
			return Err(Error::Bounds);
		}
		if !prefix.matches_reader(self.held.stage) {
			return Err(Error::Preflight(StageError::IdentityChanged.into()));
		}
		self.check_current().map_err(Error::Preflight)?;
		verify_prior(self.read_aperture()).map_err(Error::PriorReplay)?;
		self.check_current().map_err(Error::Preflight)?;
		let request = self.continuation_request(previous, successor);
		let guard = enter(request).map_err(Error::Admission)?;
		append_held(&mut self.journal, encoded_frame, guard).map_err(Error::Submitted)?;
		let current = observe_successor(
			&self.journal,
			self.held.lease,
			&self.readback,
			previous.end,
			successor.end,
			encoded_frame,
		)
		.map_err(Error::Readback)?;
		self.readback = current;
		verify_successor(self.read_aperture()).map_err(Error::SuccessorReplay)?;
		self.check_current().map_err(Error::Readback)?;
		Ok(ActiveWitnessReservation {
			reservation: self,
			head: successor,
			confirmed_checkpoint_end: prefix.end(),
			healthy: true,
		})
	}

	fn continuation_request(
		&self,
		previous: Head,
		successor: Head,
	) -> ReservedContinuationRequest<'_> {
		let job = self.held.lease.job();
		ReservedContinuationRequest {
			authority: self.authority,
			plan: self.plan,
			successor,
			previous,
			destination: job.destination_identity(),
			job: job.identity(),
			stage: self.held.stage.selection(),
			journal_directory: self.journal.journal.identity,
			segment: self.readback.identity(),
			receipt: self.receipt.observation.identity(),
		}
	}

	fn read_aperture(&self) -> ReservedJournalRead<'_> {
		ReservedJournalRead {
			readback: &self.readback,
			offset: 0,
			_same_lane: PhantomData,
		}
	}
}

fn append_held<G>(journal: &mut HeldFirstSegment<'_>, encoded: &[u8], guard: G) -> io::Result<()> {
	let result = journal
		.file
		.write_all(encoded)
		.and_then(|()| journal.file.sync_all());
	drop(guard);
	result
}

fn observe_successor(
	journal: &HeldFirstSegment<'_>,
	lease: &RecoveryWriteLease<'_>,
	previous: &RecoveryFile,
	start: u64,
	end: u64,
	submitted: &[u8],
) -> Result<RecoveryFile, WitnessReservationObservationError> {
	let job = lease.job();
	let current = open_checked_record(
		&journal.journal.file,
		std::ffi::OsStr::new(FIRST_SEGMENT),
		job.root.mount,
	)?
	.ok_or(StageError::IdentityChanged)?;
	if current.identity() != previous.identity() || current.len() != end {
		return Err(StageError::IdentityChanged.into());
	}
	journal.recheck(lease, &current)?;
	let mut bytes = [0_u8; MAX_ENCODED_CONTINUATION];
	let exact = &mut bytes[..submitted.len()];
	current
		.read_exact_at(start, exact)
		.map_err(StageError::ReadBack)?;
	if exact != submitted {
		return Err(StageError::IdentityChanged.into());
	}
	journal.recheck(lease, &current)?;
	Ok(current)
}

impl ActiveWitnessReservation<'_> {
	/// Bytes reserved on the exact unnamed receipt at original admission.
	#[must_use]
	pub const fn receipt_capacity(&self) -> u64 {
		super::native::RECEIPT_CAPACITY
	}

	/// Returns the exact accepted successor after its file barrier and read-back.
	#[must_use]
	pub const fn head(&self) -> Head {
		self.head
	}

	/// Returns the unmodified original capacity plan.
	#[must_use]
	pub const fn plan(&self) -> WitnessReservationPlan {
		self.reservation.plan()
	}

	/// Rechecks the original synchronized stage and the active journal boundary
	/// before the first suffix writer opens. Later data effects must independently
	/// track the exact new stage stamp and cursor.
	///
	/// # Errors
	/// Refuses any changed stage, journal, receipt or native qualification.
	pub fn check_before_suffix(
		&self,
		prefix: &SyncedRetainedPrefix<'_, '_>,
	) -> Result<(), WitnessReservationObservationError> {
		if !self.healthy || !prefix.matches_reader(self.reservation.held.stage) {
			return Err(StageError::IdentityChanged.into());
		}
		self.reservation.check_current()
	}
}

#[cfg(test)]
mod tests;
