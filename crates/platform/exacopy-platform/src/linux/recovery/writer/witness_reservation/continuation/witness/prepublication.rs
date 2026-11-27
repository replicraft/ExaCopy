use exacopy_endpoint::ReadView;
use exacopy_endpoint::linux_remote_qualification::RemoteDestinationFacts;
use exacopy_model::retained_prefix::Head;

use super::{
	ContinuationReservationError, ReservedContinuationRequest, ReservedJournalRead,
	SealedProtectedWitness, StageError, WitnessReservationObservationError, append_held,
	observe_successor,
};
use crate::linux::{SourceObservation, WitnessReservationAuthority, WitnessReservationPlan};

const FRAME_OVERHEAD: usize = 92;

/// The native append order for a live protected witness before public submission.
///
/// The application independently selects and checks the exact canonical frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessPrepublicationPhase {
	/// Kind 4, witnessed seal.
	Seal,
	/// Kind 5, independent whole-stream verification.
	Verify,
	/// Kind 6, fixed selected-stream metadata.
	Metadata,
	/// Kind 7, durable publication intent.
	Intent,
}

impl WitnessPrepublicationPhase {
	const fn max_bytes(self) -> usize {
		let payload = match self {
			Self::Seal => 543,
			Self::Verify => 475,
			Self::Metadata => 454,
			Self::Intent => 922,
		};
		payload + FRAME_OVERHEAD
	}

	const fn after(self) -> NativePrepublication {
		use WitnessPrepublicationPhase as Phase;
		match self {
			Phase::Seal => NativePrepublication::Next(Phase::Verify),
			Phase::Verify => NativePrepublication::Next(Phase::Metadata),
			Phase::Metadata => NativePrepublication::Next(Phase::Intent),
			Phase::Intent => NativePrepublication::IntentSynced,
		}
	}
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum NativePrepublication {
	Next(WitnessPrepublicationPhase),
	IntentSynced,
	Uncertain,
}

impl NativePrepublication {
	pub(super) const FIRST: Self = Self::Next(WitnessPrepublicationPhase::Seal);

	fn check(self, phase: WitnessPrepublicationPhase) -> Result<(), StageError> {
		if self == Self::Next(phase) {
			Ok(())
		} else if self == Self::Uncertain {
			Err(StageError::PriorBarrierFailure)
		} else {
			Err(StageError::IdentityChanged)
		}
	}
}

impl SealedProtectedWitness<'_, '_> {
	/// Returns the immutable original whole-pass reservation.
	#[must_use]
	pub const fn plan(&self) -> WitnessReservationPlan {
		self.active.plan()
	}

	/// Returns the original authority commitments selected for the held reservation.
	#[must_use]
	pub const fn authority(&self) -> WitnessReservationAuthority {
		self.active.reservation.authority()
	}

	/// Returns the facts selected by the original held destination qualification.
	///
	/// Callers compare these facts and the qualification digest to their
	/// independently verified qualification. Revalidation is a separate check.
	#[must_use]
	pub const fn qualification_facts(&self) -> &RemoteDestinationFacts {
		self.active.reservation.held.eligibility.facts()
	}

	/// Returns receipt capacity reserved on the original held anonymous inode.
	#[must_use]
	pub const fn receipt_capacity(&self) -> u64 {
		self.active.receipt_capacity()
	}

	/// Opens an independent cursor on the selected held journal at its logical EOF.
	///
	/// The aperture reads from byte zero through the exact observed extent. The
	/// original writer remains exclusively held under the same recovery lease.
	///
	/// # Errors
	/// Refuses stale stage, namespace, qualification, journal or a poisoned append.
	pub fn read_prepublication(
		&self,
		expected: Head,
	) -> Result<ReservedJournalRead<'_>, WitnessReservationObservationError> {
		self.recheck_prepublication(expected)?;
		Ok(self.active.reservation.read_aperture())
	}

	/// Reaffirms the original live stage, both aliases, and the exact held journal.
	///
	/// # Errors
	/// Refuses dropped or changed eligibility, custody or an uncertain append.
	pub fn recheck_prepublication(
		&self,
		expected: Head,
	) -> Result<(), WitnessReservationObservationError> {
		if self.phase == NativePrepublication::Uncertain {
			return Err(StageError::PriorBarrierFailure.into());
		}
		if self.head() != expected {
			return Err(StageError::IdentityChanged.into());
		}
		self.check_prepublication_custody()
	}

	/// Confirms the fixed local metadata still covered by the original full barrier.
	///
	/// This rechecks the exact barriered inode, both aliases and visible ACL/xattr
	/// absence. The selected-stream policy does not change the existing metadata.
	///
	/// # Errors
	/// Refuses wrong order, changed metadata, EOF or custody.
	pub fn check_witnessed_metadata(
		&self,
		expected: Head,
	) -> Result<SourceObservation, WitnessReservationObservationError> {
		if self.phase != NativePrepublication::Next(WitnessPrepublicationPhase::Intent) {
			self.phase.check(WitnessPrepublicationPhase::Metadata)?;
		}
		self.recheck_prepublication(expected)?;
		Ok(self.stage.observe_barriered_metadata()?)
	}

	/// Appends and independently replays one selected canonical live successor.
	///
	/// The application verifies the full proposed frame and history during the
	/// first replay callback. The final authority guard is acquired only after
	/// the native lease and stage are checked again. Pass only a guard whose
	/// destructor releases authority without performing any I/O.
	///
	/// # Errors
	/// Refuses an invalid phase, range, full replay, native observation or
	/// current admission before submission. All possibly submitted failure
	/// paths permanently poison this appender and leave artifacts in place.
	pub fn append_prepublication<G, E>(
		&mut self,
		phase: WitnessPrepublicationPhase,
		proposed: WitnessPrepublicationAppend<'_>,
		verify_proposed: impl FnOnce(ReservedJournalRead<'_>) -> Result<(), E>,
		enter: impl FnOnce(ReservedContinuationRequest<'_>) -> Result<G, E>,
		verify_successor: impl FnOnce(ReservedJournalRead<'_>) -> Result<(), E>,
	) -> Result<(), ContinuationReservationError<E>> {
		use ContinuationReservationError as Error;
		self.phase
			.check(phase)
			.map_err(|error| Error::Preflight(error.into()))?;
		if !matches_successor(self.plan(), phase, proposed) {
			return Err(Error::Bounds);
		}
		let previous = proposed.previous;
		self.recheck_prepublication(previous)
			.map_err(Error::Preflight)?;
		verify_proposed(self.active.reservation.read_aperture()).map_err(Error::PriorReplay)?;
		self.recheck_prepublication(previous)
			.map_err(Error::Preflight)?;

		let held = &mut self.active.reservation;
		let request = held.continuation_request(previous, proposed.successor);
		let guard = enter(request).map_err(Error::Admission)?;
		self.phase = NativePrepublication::Uncertain;
		append_held(&mut held.journal, proposed.encoded, guard).map_err(Error::Submitted)?;
		held.readback = observe_successor(
			&held.journal,
			held.held.lease,
			&held.readback,
			previous.end,
			proposed.successor.end,
			proposed.encoded,
		)
		.map_err(Error::Readback)?;
		verify_successor(held.read_aperture()).map_err(Error::SuccessorReplay)?;
		self.check_prepublication_custody()
			.map_err(Error::Readback)?;
		self.active.head = proposed.successor;
		self.phase = phase.after();
		Ok(())
	}

	fn check_prepublication_custody(&self) -> Result<(), WitnessReservationObservationError> {
		self.active.check_active()?;
		self.stage.recheck_observation()?;
		Ok(())
	}
}

/// Exact expected logical before/after boundaries and bounded encoded bytes.
#[derive(Clone, Copy, Debug)]
pub struct WitnessPrepublicationAppend<'encoded> {
	/// Current accepted boundary from actual semantic replay.
	pub previous: Head,
	/// Intended exact successor of the canonical frame.
	pub successor: Head,
	/// Complete independently checked frame bytes.
	pub encoded: &'encoded [u8],
}

fn matches_successor(
	plan: WitnessReservationPlan,
	phase: WitnessPrepublicationPhase,
	proposed: WitnessPrepublicationAppend<'_>,
) -> bool {
	let WitnessPrepublicationAppend {
		previous,
		successor,
		encoded,
	} = proposed;
	let Ok(width) = u64::try_from(encoded.len()) else {
		return false;
	};
	encoded.len() > FRAME_OVERHEAD
		&& encoded.len() <= phase.max_bytes()
		&& previous.end.checked_add(width) == Some(successor.end)
		&& previous.sequence.checked_add(1) == Some(successor.sequence)
		&& successor.digest != [0; 32]
		&& successor.digest != previous.digest
		&& successor.end < plan.reserve_end()
		&& successor.sequence < plan.accepted().sequence + plan.reserve_frames().get()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "../../../../../../../tests/unit/linux/witness_prepublication.rs"]
mod width_tests;
