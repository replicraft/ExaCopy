use exacopy_endpoint::ReadView;
use exacopy_model::retained_prefix::Head;

use super::{
	ActiveWitnessReservation, ContinuationReservationError, ReservedContinuationRequest,
	ReservedJournalRead, StageError, WitnessReservationObservationError, append_held,
	observe_successor,
};
use crate::linux::{
	ProtectedWitnessEffect, ProtectedWitnessError, WitnessLinkCandidate, WitnessedSuffixReadback,
};

// Maximum encoded kind 41: 605 payload bytes and 92 framing bytes.
const MAX_ENCODED_WITNESS: usize = 697;

/// Live kind-41 successor on the original journal, with the exact stage still held.
///
/// Only appending, synchronizing and independently reading back the new frame
/// can reach this state. No recovery constructor is provided.
#[must_use]
pub struct PendingProtectedWitness<'view, 'lease> {
	active: ActiveWitnessReservation<'lease>,
	stage: WitnessLinkCandidate<'view, 'lease>,
	name: [u8; 40],
}

/// Barriered witnessed stage and original reserved journal and receipt custody.
///
/// Neither resource can be detached or converted to a single-link publisher.
#[must_use]
pub struct SealedProtectedWitness<'view, 'lease> {
	active: ActiveWitnessReservation<'lease>,
	stage: WitnessedSuffixReadback<'view, 'lease>,
}

impl<'lease> ActiveWitnessReservation<'lease> {
	/// Borrows the complete held logical first segment and exact terminal stage.
	///
	/// # Errors
	/// Refuses an unrelated stage, incomplete confirmed extent or changed custody.
	pub fn replay_for_witness(
		&self,
		stage: &WitnessLinkCandidate<'_, 'lease>,
	) -> Result<ReservedJournalRead<'_>, WitnessReservationObservationError> {
		self.check_active()?;
		self.check_witness_stage(stage)?;
		Ok(self.reservation.read_aperture())
	}

	fn check_witness_stage(
		&self,
		stage: &WitnessLinkCandidate<'_, 'lease>,
	) -> Result<(), WitnessReservationObservationError> {
		if !stage.matches_reader(self.reservation.held.stage)
			|| self.confirmed_checkpoint_end != stage.length()
		{
			return Err(StageError::IdentityChanged.into());
		}
		stage.recheck_observation()?;
		Ok(())
	}

	/// Appends one selected current kind 41, retaining the original completion guard.
	///
	/// The application encodes the authenticated record and verifies the entire
	/// held successor. Its read-back callback must return the actual derived
	/// witness name. The platform does not interpret application frame formats.
	///
	/// # Errors
	/// Refuses changed custody, capacity, prior replay or admission, and reports
	/// write, full-sync or semantic read-back uncertainty after submission.
	pub fn append_witness_intent<'view, G, E>(
		mut self,
		stage: WitnessLinkCandidate<'view, 'lease>,
		successor: Head,
		encoded_frame: &[u8],
		name: [u8; 40],
		enter: impl FnOnce(ReservedContinuationRequest<'_>) -> Result<G, E>,
		verify_successor: impl FnOnce(ReservedJournalRead<'_>) -> Result<[u8; 40], E>,
	) -> Result<PendingProtectedWitness<'view, 'lease>, ContinuationReservationError<E>> {
		use ContinuationReservationError as Error;
		self.check_active().map_err(Error::Preflight)?;
		self.check_witness_stage(&stage).map_err(Error::Preflight)?;
		stage
			.check_for_witness(self.reservation.held.stage, &name)
			.map_err(|error| Error::Preflight(error.into()))?;
		let previous = self.head;
		let plan = self.reservation.plan;
		let length = u64::try_from(encoded_frame.len()).map_err(|_| Error::Bounds)?;
		if encoded_frame.is_empty()
			|| encoded_frame.len() > MAX_ENCODED_WITNESS
			|| previous.end.checked_add(length) != Some(successor.end)
			|| previous.sequence.checked_add(1) != Some(successor.sequence)
			|| successor.digest == [0; 32]
			|| successor.digest == previous.digest
			|| successor.end >= plan.reserve_end()
			|| successor.sequence >= plan.accepted().sequence + plan.reserve_frames().get()
		{
			return Err(Error::Bounds);
		}
		let request = self.reservation.continuation_request(previous, successor);
		let guard = enter(request).map_err(Error::Admission)?;
		append_held(&mut self.reservation.journal, encoded_frame, guard)
			.map_err(Error::Submitted)?;
		self.reservation.readback = observe_successor(
			&self.reservation.journal,
			self.reservation.held.lease,
			&self.reservation.readback,
			previous.end,
			successor.end,
			encoded_frame,
		)
		.map_err(Error::Readback)?;
		let read_name =
			verify_successor(self.reservation.read_aperture()).map_err(Error::SuccessorReplay)?;
		if read_name != name {
			return Err(Error::Readback(StageError::IdentityChanged.into()));
		}
		self.check_active().map_err(Error::Readback)?;
		self.check_witness_stage(&stage).map_err(Error::Readback)?;
		self.head = successor;
		Ok(PendingProtectedWitness {
			active: self,
			stage,
			name,
		})
	}
}

impl<'view, 'lease> PendingProtectedWitness<'view, 'lease> {
	/// Consumes the exact live witness intent and creates one protected hard link.
	///
	/// Invoke on the credential-stable qualified lane that opened the stage.
	/// Every actual effect requires a fresh synchronous guard after probes.
	///
	/// # Errors
	/// Refuses changed custody or authority. Failed or ambiguous submission
	/// consumes the capability and retains all evidence.
	pub fn link_protected_witness<G, E>(
		self,
		mut enter: impl FnMut(Head, ProtectedWitnessEffect) -> Result<G, E>,
	) -> Result<SealedProtectedWitness<'view, 'lease>, ProtectedWitnessError<E>> {
		use ProtectedWitnessError as Error;
		let check = |after_link| {
			self.active
				.check_active()
				.map_err(|cause| Error::Custody { after_link, cause })
		};
		check(false)?;
		let stage = self.stage.link_checked_witness(self.name, |effect| {
			let after_link = effect != ProtectedWitnessEffect::Link;
			check(after_link)?;
			enter(self.active.head, effect).map_err(|error| {
				if after_link {
					Error::BarrierAdmission(error)
				} else {
					Error::Admission(error)
				}
			})
		})?;
		check(true)?;
		Ok(SealedProtectedWitness {
			active: self.active,
			stage,
		})
	}
}

impl<'view, 'lease> SealedProtectedWitness<'view, 'lease> {
	/// Borrows the barriered original two-link stage for independent verification.
	#[must_use]
	pub const fn stage(&self) -> &WitnessedSuffixReadback<'view, 'lease> {
		&self.stage
	}

	/// Exact accepted kind-41 boundary under the held reservation.
	#[must_use]
	pub const fn head(&self) -> Head {
		self.active.head
	}
}
