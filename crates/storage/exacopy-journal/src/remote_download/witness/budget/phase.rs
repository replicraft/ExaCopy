//! Reachable suffix capacities for the selected witnessed grammar.

use crate::frame::FrameKind as Kind;

use super::super::super::MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES;
use super::super::records::RemoteWitnessCloseoutRecord;
use super::super::{MAX_REMOTE_RECEIPT_READY_BYTES, MAX_REMOTE_WITNESS_INTENT_BYTES};
use super::{Capacity, Error, WitnessedPassBudget};

/// Independently observed selected journal phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessedPassProgress {
	/// The original accepted boundary before kind 40.
	BeforeContinuation,
	/// Kind 40 and the specified prefix of the planned checkpoint schedule.
	Continued {
		/// Number of completed scheduled checkpoints, excluding the retained prefix.
		completed_checkpoints: u16,
	},
	/// Kind 41 at complete source extent.
	WitnessIntent,
	/// Kind 4 accepted.
	Sealed,
	/// Kind 5 accepted.
	Verified,
	/// Kind 6 accepted.
	MetadataReady,
	/// Kind 7 accepted.
	PublishIntent,
	/// Positive kind 8 accepted.
	PublishedObserved,
	/// Kind 9 accepted.
	Durable,
	/// Kind 42 accepted.
	ReceiptReady,
	/// Kind 18 accepted.
	ReceiptCommitted,
	/// Kind 39 accepted from a pre-publication phase.
	Retired {
		/// Phase from which the selected pass retired.
		from: WitnessedRetirementPhase,
	},
	/// The fresh kind 37 accepted from the retirement path.
	FreshAllocated {
		/// Phase from which the selected pass retired.
		from: WitnessedRetirementPhase,
	},
	/// The fresh kind 2 accepted from the retirement path.
	FreshPrepared {
		/// Phase from which the selected pass retired.
		from: WitnessedRetirementPhase,
	},
}

/// Accepted pre-intent phase before a selected retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessedRetirementPhase {
	/// The continued capture has no signed witness intent.
	Continued {
		/// Number of completed scheduled checkpoints.
		completed_checkpoints: u16,
	},
	/// Kind 41 accepted.
	WitnessIntent,
	/// Kind 4 accepted.
	Sealed,
	/// Kind 5 accepted.
	Verified,
	/// Kind 6 accepted.
	MetadataReady,
}

#[derive(Clone, Copy)]
enum Position {
	Coverage,
	Witness,
	Seal,
	Verify,
	Metadata,
	Intent,
	Observed,
	Durable,
	Ready,
	Complete,
	Retired,
	Allocated,
	Prepared,
}

// The independent width checker derives these narrower alternatives from the
// canonical layouts for two positive kind-8 outcomes and witness-absent kind 39.
const MAX_POSITIVE_OBSERVATION_PAYLOAD: usize = 467;
const MAX_UNWITNESSED_RETIREMENT_PAYLOAD: usize = 794;

impl Position {
	fn required(self, fresh: bool) -> Result<Capacity, Error> {
		let linear = |kind, successor: Self| record(kind)?.plus(successor.required(fresh)?);
		Ok(match self {
			Self::Coverage => linear(Kind::RemoteWitnessIntent, Self::Witness)?.max(
				pre_intent_alternatives(fresh, MAX_UNWITNESSED_RETIREMENT_PAYLOAD)?,
			),
			Self::Witness => linear(Kind::StageSealed, Self::Seal)?
				.max(witnessed_pre_intent_alternatives(fresh)?),
			Self::Seal => linear(Kind::VerificationRecorded, Self::Verify)?
				.max(witnessed_pre_intent_alternatives(fresh)?),
			Self::Verify => linear(Kind::MetadataRecorded, Self::Metadata)?
				.max(witnessed_pre_intent_alternatives(fresh)?),
			Self::Metadata => linear(Kind::PublishIntent, Self::Intent)?
				.max(witnessed_pre_intent_alternatives(fresh)?),
			Self::Intent => Capacity::frame(MAX_POSITIVE_OBSERVATION_PAYLOAD)?
				.plus(Self::Observed.required(fresh)?)?
				.max(record(Kind::PublishObserved)?),
			Self::Observed => linear(Kind::DurabilityRecorded, Self::Durable)?,
			Self::Durable => linear(Kind::RemoteReceiptReady, Self::Ready)?,
			Self::Ready => linear(Kind::ReceiptCommitted, Self::Complete)?,
			Self::Complete => Capacity::default(),
			Self::Retired => linear(Kind::RemoteStageAllocated, Self::Allocated)?,
			Self::Allocated => {
				linear(Kind::EntryPrepared, Self::Prepared)?.max(record(Kind::FailureRecorded)?)
			}
			Self::Prepared => record(Kind::FailureRecorded)?,
		})
	}
}

fn record_payload(kind: Kind) -> Result<usize, Error> {
	match kind {
		Kind::RemoteWitnessIntent => Ok(MAX_REMOTE_WITNESS_INTENT_BYTES),
		Kind::RemoteReceiptReady => Ok(MAX_REMOTE_RECEIPT_READY_BYTES),
		Kind::RemoteStageAllocated | Kind::EntryPrepared | Kind::FailureRecorded => {
			Ok(MAX_REMOTE_DOWNLOAD_PAYLOAD_BYTES)
		}
		_ => RemoteWitnessCloseoutRecord::payload_cap(kind).ok_or(Error::Progress),
	}
}

fn record(kind: Kind) -> Result<Capacity, Error> {
	Capacity::frame(record_payload(kind)?)
}

fn pre_intent_alternatives(fresh: bool, retirement_payload: usize) -> Result<Capacity, Error> {
	let failure = record(Kind::FailureRecorded)?;
	if fresh {
		Ok(failure
			.max(Capacity::frame(retirement_payload)?.plus(Position::Retired.required(fresh)?)?))
	} else {
		Ok(failure)
	}
}

fn witnessed_pre_intent_alternatives(fresh: bool) -> Result<Capacity, Error> {
	pre_intent_alternatives(fresh, record_payload(Kind::RemoteCaptureRetired)?)
}

pub(super) fn initial(fresh: bool) -> Result<Capacity, Error> {
	Position::Coverage.required(fresh)
}

impl WitnessedPassProgress {
	pub(super) fn required(self, plan: WitnessedPassBudget) -> Result<(u16, Capacity), Error> {
		let planned = plan.checkpoint_count();
		let fresh = plan.allows_fresh_retirement();
		let (completed, phase_frames, position) = match self {
			Self::BeforeContinuation => {
				let bytes = plan
					.reserved_end
					.checked_sub(plan.boundary.offset)
					.ok_or(Error::Arithmetic)?;
				return Ok((
					0,
					Capacity {
						bytes,
						frames: plan.reserved_frames,
					},
				));
			}
			Self::Continued {
				completed_checkpoints,
			} => (completed_checkpoints, 0, Position::Coverage),
			Self::WitnessIntent => (planned, 1, Position::Witness),
			Self::Sealed => (planned, 2, Position::Seal),
			Self::Verified => (planned, 3, Position::Verify),
			Self::MetadataReady => (planned, 4, Position::Metadata),
			Self::PublishIntent => (planned, 5, Position::Intent),
			Self::PublishedObserved => (planned, 6, Position::Observed),
			Self::Durable => (planned, 7, Position::Durable),
			Self::ReceiptReady => (planned, 8, Position::Ready),
			Self::ReceiptCommitted => (planned, 9, Position::Complete),
			Self::Retired { from } if fresh => {
				from.after_retirement(planned, 1, Position::Retired)?
			}
			Self::FreshAllocated { from } if fresh => {
				from.after_retirement(planned, 2, Position::Allocated)?
			}
			Self::FreshPrepared { from } if fresh => {
				from.after_retirement(planned, 3, Position::Prepared)?
			}
			_ => return Err(Error::Progress),
		};
		let uncompleted = planned.checked_sub(completed).ok_or(Error::Progress)?;
		let frames_used = completed
			.checked_add(1)
			.and_then(|frames| frames.checked_add(phase_frames))
			.ok_or(Error::Arithmetic)?;
		let mut journal = position.required(fresh)?;
		if matches!(self, Self::Continued { .. }) {
			journal = Capacity::checkpoints(uncompleted)?.plus(journal)?;
		}
		Ok((frames_used, journal))
	}
}

impl WitnessedRetirementPhase {
	fn after_retirement(
		self,
		planned: u16,
		fresh_frames: u16,
		position: Position,
	) -> Result<(u16, u16, Position), Error> {
		let (completed, earlier) = match self {
			Self::Continued {
				completed_checkpoints,
			} => (completed_checkpoints, 0u16),
			Self::WitnessIntent => (planned, 1),
			Self::Sealed => (planned, 2),
			Self::Verified => (planned, 3),
			Self::MetadataReady => (planned, 4),
		};
		let frames = earlier.checked_add(fresh_frames).ok_or(Error::Arithmetic)?;
		Ok((completed, frames, position))
	}
}
