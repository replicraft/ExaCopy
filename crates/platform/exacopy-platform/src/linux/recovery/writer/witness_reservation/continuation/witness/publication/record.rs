use exacopy_model::retained_prefix::Head;
use exacopy_model::witnessed_publication::RenameSubmission;

use super::super::{ContinuationReservationError, append_held, observe_successor};
use super::{ReservedJournalRead, StageError, WitnessPublication, WitnessPublicationObservation};
use crate::linux::WitnessReservationPlan;

// The largest canonical selector-2 kind-8 payload, including uncertainty tags,
// is 476 bytes. The original journal frame adds 92 bytes.
const FRAME_OVERHEAD: usize = 92;
const MAX_OBSERVATION_FRAME: usize = 476 + FRAME_OVERHEAD;

/// One appended outcome assembled from the exact actual native submission.
///
/// The platform owns the descriptor and checks the reserve. The trusted
/// application encodes and verifies the selected canonical outcome.
#[derive(Debug)]
pub struct WitnessObservationAppend {
	/// Actual current durable kind-7 boundary.
	pub previous: Head,
	/// Exact proposed kind-8 boundary.
	pub successor: Head,
	/// Complete bounded on-disk frame, including framing.
	pub encoded: Vec<u8>,
}

impl WitnessPublication<'_, '_> {
	/// Records the observed result of the one already submitted native call.
	///
	/// The builder receives the original consumed model submission, exact native
	/// fact and independent held journal cursor. The caller must consume the token
	/// in its original model and encode exactly that observation. Both verification
	/// callbacks confirm the complete selected journal, with the proposed frame and
	/// with the actual readback respectively. No fresh grant can be required to
	/// record this existing outcome. This capability authorizes no new rename,
	/// namespace effect or durability action.
	///
	/// # Errors
	/// Any attempt spends the original one-shot outcome capability. A failure
	/// retains the original lease, physical observation and any submitted bytes.
	/// No subsequent append is available from the same outcome.
	pub fn record_observation<E>(
		&mut self,
		build: impl FnOnce(
			RenameSubmission,
			&WitnessPublicationObservation,
			ReservedJournalRead<'_>,
		) -> Result<WitnessObservationAppend, E>,
		verify_proposed: impl FnOnce(
			ReservedJournalRead<'_>,
			&WitnessObservationAppend,
		) -> Result<(), E>,
		verify_successor: impl FnOnce(
			ReservedJournalRead<'_>,
			&WitnessObservationAppend,
		) -> Result<(), E>,
	) -> Result<Head, ContinuationReservationError<E>> {
		use ContinuationReservationError as Error;

		let submission = self
			.submission
			.take()
			.ok_or_else(|| Error::Preflight(StageError::PriorBarrierFailure.into()))?;
		let active = &mut self.held.active;
		active.check_active().map_err(Error::Preflight)?;
		let previous = active.head();
		if submission.binding().0 != previous {
			return Err(Error::Preflight(StageError::IdentityChanged.into()));
		}
		let proposed = build(
			submission,
			&self.observation,
			active.reservation.read_aperture(),
		)
		.map_err(Error::PriorReplay)?;
		if proposed.previous != previous || !matches_bounds(active.plan(), &proposed) {
			return Err(Error::Bounds);
		}
		active.check_active().map_err(Error::Preflight)?;
		verify_proposed(active.reservation.read_aperture(), &proposed)
			.map_err(Error::PriorReplay)?;
		active.check_active().map_err(Error::Preflight)?;

		let result = (|| {
			let reservation = &mut active.reservation;
			append_held(&mut reservation.journal, &proposed.encoded, ())
				.map_err(Error::Submitted)?;
			reservation.readback = observe_successor(
				&reservation.journal,
				reservation.held.lease,
				&reservation.readback,
				previous.end,
				proposed.successor.end,
				&proposed.encoded,
			)
			.map_err(Error::Readback)?;
			verify_successor(reservation.read_aperture(), &proposed)
				.map_err(Error::SuccessorReplay)?;
			active.check_active().map_err(Error::Readback)?;
			Ok(())
		})();
		if let Err(error) = result {
			active.stop();
			return Err(error);
		}
		active.head = proposed.successor;
		self.observation_head = Some(proposed.successor);
		Ok(proposed.successor)
	}
}

fn matches_bounds(plan: WitnessReservationPlan, proposed: &WitnessObservationAppend) -> bool {
	let WitnessObservationAppend {
		previous,
		successor,
		encoded,
	} = proposed;
	let Ok(width) = u64::try_from(encoded.len()) else {
		return false;
	};
	encoded.len() > FRAME_OVERHEAD
		&& encoded.len() <= MAX_OBSERVATION_FRAME
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
#[path = "../../../../../../../../tests/unit/witness_observation_bounds.rs"]
mod bounds_tests;
