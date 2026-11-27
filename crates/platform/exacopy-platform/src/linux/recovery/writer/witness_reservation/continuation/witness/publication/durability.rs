use exacopy_endpoint::linux_remote_qualification::RemoteDestinationFacts;
use exacopy_model::retained_prefix::Head;

use super::super::{append_held, observe_successor};
use super::{ReservedJournalRead, StageError, WitnessPublication, WitnessPublicationObservation};
use crate::linux::{
	FileIdentity, RetainedPrefixSelection, SourceObservation, WitnessReservationAuthority,
	WitnessReservationObservationError, WitnessReservationPlan,
};

const FRAME_OVERHEAD: usize = 92;
const MAX_DURABILITY_FRAME: usize = 551 + FRAME_OVERHEAD;

/// One of the ordered, independently admitted publication durability effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessDurabilityEffect {
	/// Fully synchronize the held two-link published file.
	File,
	/// Fully synchronize the original private staging directory.
	StageDirectory,
	/// Fully synchronize the held public target parent.
	DestinationDirectory,
	/// Fully synchronize the held protected job root.
	JobDirectory,
	/// Append and fully synchronize the checked kind-9 frame.
	JournalAppend,
}

const BARRIERS: [WitnessDurabilityEffect; 4] = [
	WitnessDurabilityEffect::File,
	WitnessDurabilityEffect::StageDirectory,
	WitnessDurabilityEffect::DestinationDirectory,
	WitnessDurabilityEffect::JobDirectory,
];

/// Exact live binding delivered to the application immediately before an effect.
#[derive(Clone, Copy, Debug)]
pub struct WitnessDurabilityRequest<'name> {
	/// One synchronous effect being requested.
	pub effect: WitnessDurabilityEffect,
	/// Exact accepted positive kind-8 boundary.
	pub observation: Head,
	/// Exact proposed kind-9 boundary.
	pub successor: Head,
	/// Original private stage and public target selection.
	pub stage: RetainedPrefixSelection<'name>,
	/// Held protected job root.
	pub job: FileIdentity,
	/// Held public target parent.
	pub destination: FileIdentity,
	/// Original grant, retention consent and qualification commitments.
	pub authority: WitnessReservationAuthority,
}

/// Bounded canonical durability frame prepared by the trusted application.
#[derive(Debug)]
pub struct WitnessDurabilityAppend {
	/// Actual kind-8 predecessor.
	pub previous: Head,
	/// Exact kind-9 successor.
	pub successor: Head,
	/// Complete prospective on-disk frame.
	pub encoded: Vec<u8>,
}

/// Refusal or uncertainty while establishing durability of an observed publication.
#[derive(Debug)]
pub enum WitnessDurabilityError<E> {
	/// The exact positive outcome or held custody could not be confirmed.
	Preflight(WitnessReservationObservationError),
	/// The proposed successor does not fit the exact original reservation.
	Bounds,
	/// Independent application interpretation rejected the exact prior.
	PriorReplay(E),
	/// Independent application replay rejected the proposed transcript.
	ProposedReplay(E),
	/// The current application authority denied the specific effect.
	Admission {
		/// Refused effect.
		effect: WitnessDurabilityEffect,
		/// Original application refusal.
		cause: E,
	},
	/// Native probes failed before this barrier was submitted.
	BarrierPreflight {
		/// Effect whose binding could not be confirmed.
		effect: WitnessDurabilityEffect,
		/// Original native observation error.
		cause: StageError,
	},
	/// The actual fsync returned a failure after submission.
	BarrierSubmitted {
		/// Effect whose persistence is unconfirmed.
		effect: WitnessDurabilityEffect,
		/// Original native sync error.
		cause: StageError,
	},
	/// The submitted journal append or sync had an uncertain outcome.
	Submitted(std::io::Error),
	/// Independent native readback did not confirm the submitted successor.
	Readback(WitnessReservationObservationError),
	/// Independent application replay did not confirm the submitted successor.
	SuccessorReplay(E),
}

pub(super) enum Progress {
	Unspent,
	Spent,
	Confirmed(Head),
}

impl WitnessPublication<'_, '_> {
	/// The qualification facts originally selected for this held publication.
	#[must_use]
	pub const fn qualification_facts(&self) -> &RemoteDestinationFacts {
		self.held.qualification_facts()
	}

	/// Exact durable, independently reread kind-9 boundary after all barriers.
	#[must_use]
	pub const fn durability_head(&self) -> Option<Head> {
		if let Progress::Confirmed(head) = self.durability {
			Some(head)
		} else {
			None
		}
	}

	/// Establishes durability of the exact native publication already recorded.
	///
	/// The trusted builder confirms an accepted positive kind 8 against the
	/// supplied native observation and original held journal. Both replay
	/// callbacks check the full selected history against the proposed successor.
	/// The admission callback checks the current bound grant, consent and
	/// qualification anew for each effect, after native probes. It must perform
	/// no I/O, await, credential changes or lease reentry. Its guard remains
	/// held through the requested fsync or journal write and sync.
	///
	/// # Errors
	/// The first attempt spends this capability before any check. Refusal or
	/// uncertainty retains original publication facts and custody without
	/// allowing another attempt, a rename or a receipt effect.
	pub fn record_durability<G, E>(
		&mut self,
		expected_kind8: Head,
		build: impl FnOnce(
			SourceObservation,
			ReservedJournalRead<'_>,
		) -> Result<WitnessDurabilityAppend, E>,
		verify_proposed: impl FnOnce(ReservedJournalRead<'_>, &WitnessDurabilityAppend) -> Result<(), E>,
		mut enter: impl FnMut(WitnessDurabilityRequest<'_>) -> Result<G, E>,
		verify_successor: impl FnOnce(
			ReservedJournalRead<'_>,
			&WitnessDurabilityAppend,
		) -> Result<(), E>,
	) -> Result<Head, WitnessDurabilityError<E>> {
		use WitnessDurabilityError as Error;

		if !matches!(self.durability, Progress::Unspent) {
			return Err(Error::Preflight(StageError::PriorBarrierFailure.into()));
		}
		self.durability = Progress::Spent;

		let active = &mut self.held.active;
		// A premature attempt still spends durability, while the caller can
		// independently record the original, already-submitted rename outcome.
		let WitnessPublicationObservation::Published(published) = self.observation else {
			return Err(Error::Preflight(StageError::PriorBarrierFailure.into()));
		};
		if self.observation_head != Some(expected_kind8) || active.head() != expected_kind8 {
			return Err(Error::Preflight(StageError::IdentityChanged.into()));
		}

		let result = (|| {
			let published_names = self
				.held
				.stage
				.held_names()
				.map_err(|cause| Error::Preflight(cause.into()))?;
			active.check_active().map_err(Error::Preflight)?;
			let proposed =
				build(published, active.reservation.read_aperture()).map_err(Error::PriorReplay)?;
			if proposed.previous != expected_kind8 || !matches_bounds(active.plan(), &proposed) {
				return Err(Error::Bounds);
			}
			active.check_active().map_err(Error::Preflight)?;
			verify_proposed(active.reservation.read_aperture(), &proposed)
				.map_err(Error::ProposedReplay)?;

			let original = &active.reservation;
			let job = original.held.lease.job();
			let mut admit = |effect| {
				enter(WitnessDurabilityRequest {
					effect,
					observation: expected_kind8,
					successor: proposed.successor,
					stage: original.held.stage.selection(),
					job: job.identity(),
					destination: job.destination_identity(),
					authority: original.authority,
				})
				.map_err(|cause| Error::Admission { effect, cause })
			};
			for effect in BARRIERS {
				active.check_active().map_err(Error::Preflight)?;
				published_names
					.sync_published(effect, published, || admit(effect))?
					.map_err(|cause| barrier_failure(effect, cause))?;
			}

			active.check_active().map_err(Error::Preflight)?;
			let _pins = published_names
				.pin_published(published)
				.map_err(|cause| Error::Preflight(cause.into()))?;
			let guard = admit(WitnessDurabilityEffect::JournalAppend)?;
			let reservation = &mut active.reservation;
			append_held(&mut reservation.journal, &proposed.encoded, guard)
				.map_err(Error::Submitted)?;
			reservation.readback = observe_successor(
				&reservation.journal,
				reservation.held.lease,
				&reservation.readback,
				expected_kind8.end,
				proposed.successor.end,
				&proposed.encoded,
			)
			.map_err(Error::Readback)?;
			verify_successor(reservation.read_aperture(), &proposed)
				.map_err(Error::SuccessorReplay)?;
			active.check_active().map_err(Error::Readback)?;
			published_names
				.pin_published(published)
				.map_err(|cause| Error::Readback(cause.into()))?;
			Ok(proposed.successor)
		})();
		match result {
			Ok(head) => {
				active.head = head;
				self.durability = Progress::Confirmed(head);
				Ok(head)
			}
			Err(error) => {
				active.stop();
				Err(error)
			}
		}
	}
}

fn barrier_failure<E>(
	effect: WitnessDurabilityEffect,
	cause: StageError,
) -> WitnessDurabilityError<E> {
	match cause {
		StageError::BarrierFailed(_) | StageError::DirectoryBarrierFailed(_) => {
			WitnessDurabilityError::BarrierSubmitted { effect, cause }
		}
		_ => WitnessDurabilityError::BarrierPreflight { effect, cause },
	}
}

fn matches_bounds(plan: WitnessReservationPlan, proposed: &WitnessDurabilityAppend) -> bool {
	let WitnessDurabilityAppend {
		previous,
		successor,
		encoded,
	} = proposed;
	let Ok(width) = u64::try_from(encoded.len()) else {
		return false;
	};
	encoded.len() > FRAME_OVERHEAD
		&& encoded.len() <= MAX_DURABILITY_FRAME
		&& previous.end.checked_add(width) == Some(successor.end)
		&& previous.sequence.checked_add(1) == Some(successor.sequence)
		&& successor.digest != [0; 32]
		&& successor.digest != previous.digest
		&& successor.end < plan.reserve_end()
		&& successor.sequence < plan.accepted().sequence + plan.reserve_frames().get()
}

#[cfg(test)]
mod tests;
