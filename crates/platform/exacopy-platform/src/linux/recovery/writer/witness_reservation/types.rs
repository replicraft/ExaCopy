use std::convert::Infallible;
use std::num::NonZeroU64;
use std::{error, fmt};

use exacopy_model::retained_prefix::Head;

use crate::linux::{FileIdentity, RemoteDestinationEligibilityError, StageError};

use super::RetainedPrefixSelection;

const MAX_SEGMENT_END: u64 = 64 * 1024 * 1024;

/// The structural projection of the storage owner's checked whole-pass plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessReservationPlan {
	accepted: Head,
	reserve_end: u64,
	reserve_frames: NonZeroU64,
}

impl WitnessReservationPlan {
	/// Binds a positive reservation to a nonempty accepted first-segment boundary.
	///
	/// # Errors
	/// Refuses an empty boundary, out-of-range end or exhausted sequence space.
	pub fn new(
		accepted: Head,
		reserve_end: u64,
		reserve_frames: NonZeroU64,
	) -> Result<Self, WitnessReservationError> {
		if accepted.sequence == 0
			|| accepted.digest == [0; 32]
			|| accepted.end == 0
			|| reserve_end <= accepted.end
			|| reserve_end > MAX_SEGMENT_END
			|| accepted
				.sequence
				.checked_add(reserve_frames.get())
				.is_none()
		{
			return Err(WitnessReservationError::Bounds);
		}
		Ok(Self {
			accepted,
			reserve_end,
			reserve_frames,
		})
	}

	/// Returns the exact accepted boundary selected by the caller's semantic replay.
	#[must_use]
	pub const fn accepted(self) -> Head {
		self.accepted
	}

	/// Returns the exclusive upper byte bound reserved for the selected pass.
	#[must_use]
	pub const fn reserve_end(self) -> u64 {
		self.reserve_end
	}

	/// Returns the requested number of subsequent sequence positions.
	#[must_use]
	pub const fn reserve_frames(self) -> NonZeroU64 {
		self.reserve_frames
	}

	pub(super) const fn allocation(self) -> (u64, u64) {
		(self.accepted.end, self.reserve_end - self.accepted.end)
	}
}

/// Independently selected commitments that the caller admits under the live gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessReservationAuthority {
	/// Exact operation-2 qualification commitment.
	pub qualification: [u8; 32],
	/// Exact current base grant commitment.
	pub base_grant: [u8; 32],
	/// Exact current witness-retention approval commitment.
	pub retention_approval: [u8; 32],
}

/// One native request covered by a separately acquired live authorization guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessReservationEffect {
	/// Create an unnamed owned receipt under the held private job.
	ReceiptCreate,
	/// Reserve fixed capacity on the exact still-unnamed receipt.
	ReceiptAllocate,
	/// Reserve the positive journal span beginning at the accepted logical EOF.
	JournalAllocate,
}

pub(super) type Effect = WitnessReservationEffect;

/// Exact binding rechecked by the live same-lane authorization gate for one syscall.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessReservationGateRequest<'names> {
	/// Effect about to run.
	pub effect: WitnessReservationEffect,
	/// Independently selected operation-2, live grant and consent commitments.
	pub authority: WitnessReservationAuthority,
	/// Exact caller-accepted journal boundary and positive reservation bound.
	pub plan: WitnessReservationPlan,
	/// Current held destination identity.
	pub destination: FileIdentity,
	/// Exact held private job identity.
	pub job: FileIdentity,
	/// Exact selected stage/target names and held stage identities.
	pub stage: RetainedPrefixSelection<'names>,
	/// Exact held private journal directory.
	pub journal_directory: FileIdentity,
	/// Exact held first segment.
	pub segment: FileIdentity,
	/// Exact held anonymous receipt identity, present after creation.
	pub receipt: Option<FileIdentity>,
}

/// Native observation causing a reservation refusal or reconciliation.
#[derive(Debug)]
#[non_exhaustive]
pub enum WitnessReservationObservationError {
	/// The witnessed profile requires an unprivileged executor UID.
	PrivilegedExecution,
	/// Held lease, metadata or bounded filesystem operation failed.
	Native(StageError),
	/// Held destination eligibility could not be reaffirmed.
	Eligibility(RemoteDestinationEligibilityError),
}

impl From<StageError> for WitnessReservationObservationError {
	fn from(error: StageError) -> Self {
		Self::Native(error)
	}
}

impl From<RemoteDestinationEligibilityError> for WitnessReservationObservationError {
	fn from(error: RemoteDestinationEligibilityError) -> Self {
		Self::Eligibility(error)
	}
}

impl fmt::Display for WitnessReservationObservationError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::PrivilegedExecution => {
				formatter.write_str("witness reservation requires a non-root executor")
			}
			Self::Native(error) => error.fmt(formatter),
			Self::Eligibility(error) => error.fmt(formatter),
		}
	}
}

impl error::Error for WitnessReservationObservationError {
	fn source(&self) -> Option<&(dyn error::Error + 'static)> {
		match self {
			Self::PrivilegedExecution => None,
			Self::Native(error) => Some(error),
			Self::Eligibility(error) => Some(error),
		}
	}
}

/// Failure before or during one native reservation attempt.
#[derive(Debug)]
#[non_exhaustive]
pub enum WitnessReservationError<E = Infallible> {
	/// Requested interval is outside the structural first-segment bound.
	Bounds,
	/// Independently selected operation-2 digest differs from native eligibility.
	QualificationMismatch,
	/// The initial observations refused before any allocation.
	Preflight(WitnessReservationObservationError),
	/// The current live gate refused the indicated effect before it ran.
	Gate {
		/// Effect that was about to run.
		effect: WitnessReservationEffect,
		/// Exact application authorization failure.
		source: E,
	},
	/// The indicated syscall was submitted and failed, or a later recheck failed.
	AfterEffect {
		/// Most recent syscall whose effect must be considered.
		effect: WitnessReservationEffect,
		/// Native failure or changed observation.
		source: WitnessReservationObservationError,
	},
}

impl<E> WitnessReservationError<E> {
	pub(super) fn after(
		effect: WitnessReservationEffect,
		source: impl Into<WitnessReservationObservationError>,
	) -> Self {
		Self::AfterEffect {
			effect,
			source: source.into(),
		}
	}
}

impl<E: fmt::Display> fmt::Display for WitnessReservationError<E> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Bounds => formatter.write_str("witness journal reservation is outside bounds"),
			Self::QualificationMismatch => formatter.write_str("witness qualification differs"),
			Self::Preflight(source) => write!(formatter, "reservation preflight refused: {source}"),
			Self::Gate { effect, source } => {
				write!(formatter, "reservation gate refused {effect:?}: {source}")
			}
			Self::AfterEffect { effect, source } => write!(
				formatter,
				"reservation failed after submitting {effect:?}: {source}"
			),
		}
	}
}

impl<E: error::Error + 'static> error::Error for WitnessReservationError<E> {
	fn source(&self) -> Option<&(dyn error::Error + 'static)> {
		match self {
			Self::Bounds | Self::QualificationMismatch => None,
			Self::Preflight(source) | Self::AfterEffect { source, .. } => Some(source),
			Self::Gate { source, .. } => Some(source),
		}
	}
}
