//! Pure capacity projections for one selected witnessed retained pass.

use std::fmt;
use std::num::NonZeroU16;
use std::ops::Range;

use crate::frame::FRAME_OVERHEAD_BYTES;
use crate::{MAX_FIRST_SEGMENT_BYTES, StreamLength};

use super::super::continuation::MAX_REMOTE_CONTINUATION_PAYLOAD_BYTES;
use super::super::continuation::checkpoint::MAX_REMOTE_CONTINUED_CHECKPOINT_BYTES;
use super::super::replay::{MAX_REMOTE_REPLAY_ATTEMPTS, RemoteReplayBoundary};
use super::super::{MAX_REMOTE_CHECKPOINT_BYTES, MAX_REMOTE_CHECKPOINTS};
use super::MAX_REMOTE_WITNESS_RECEIPT_BYTES;

mod phase;

pub use phase::{WitnessedPassProgress, WitnessedRetirementPhase};

/// Exact caller-selected origin and capacity required for one witnessed pass.
///
/// The caller independently authenticates the origin, source extent and prior
/// run count. This projection conveys no authority and reserves no resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessedPassBudget {
	boundary: RemoteReplayBoundary,
	retained_end: StreamLength,
	fresh_source_length: StreamLength,
	checkpoint_count: u16,
	new_run: NonZeroU16,
	reserved_end: u64,
	reserved_frames: u16,
	reserved_sequence: u64,
}

/// Remaining conservative journal and receipt capacity at a checked position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WitnessedPassRemaining {
	journal: Capacity,
}

impl WitnessedPassRemaining {
	/// Maximum additional framed bytes on any remaining path.
	pub const fn journal_bytes(self) -> u64 {
		self.journal.bytes
	}

	/// Maximum additional frame slots on any remaining path.
	pub const fn journal_frames(self) -> u16 {
		self.journal.frames
	}

	/// Capacity of the reserved canonical receipt artifact.
	pub const fn receipt_bytes(self) -> u16 {
		MAX_REMOTE_WITNESS_RECEIPT_BYTES
	}
}

/// Refusal to project capacity for a witnessed pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WitnessedPassBudgetError {
	/// The supplied boundary cannot be the selected frame position.
	Boundary,
	/// The fresh source is shorter than the selected retained extent.
	SourceExtent,
	/// The suffix needs more checkpoints than the selected profile permits.
	CheckpointLimit,
	/// No additional logical pass is available.
	RunLimit,
	/// The whole pass would exceed the first segment byte limit.
	SegmentLimit,
	/// The whole pass would exhaust the frame sequence.
	SequenceLimit,
	/// The caller-selected progress lies outside this plan.
	Progress,
	/// The observed position leaves insufficient reserved byte or frame capacity.
	ReservationExceeded,
	/// A checked capacity calculation failed.
	Arithmetic,
}

impl fmt::Display for WitnessedPassBudgetError {
	fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
		output.write_str(match self {
			Self::Boundary => "witnessed pass boundary is inconsistent",
			Self::SourceExtent => "fresh source is shorter than the retained extent",
			Self::CheckpointLimit => "witnessed pass exceeds the checkpoint limit",
			Self::RunLimit => "witnessed pass exceeds the logical run limit",
			Self::SegmentLimit => "witnessed pass exceeds the first segment limit",
			Self::SequenceLimit => "witnessed pass exceeds the frame sequence limit",
			Self::Progress => "witnessed pass progress is outside the selected plan",
			Self::ReservationExceeded => "remaining path exceeds the witnessed pass reservation",
			Self::Arithmetic => "witnessed pass capacity arithmetic overflowed",
		})
	}
}

impl std::error::Error for WitnessedPassBudgetError {}

use WitnessedPassBudgetError as Error;

impl WitnessedPassBudget {
	/// Plans capacity from the exact accepted boundary before kind 40.
	///
	/// The source extent is independently selected. The run count includes
	/// abandoned and continued passes already consumed across the job.
	/// This is arithmetic over the supplied extents. Callers also need the
	/// authenticated positive retained prefix required for kind 40.
	///
	/// # Errors
	/// Refuses insufficient logical runs, checkpoint, segment or sequence space,
	/// an inconsistent origin, a shorter source, or arithmetic overflow.
	pub fn plan(
		boundary: RemoteReplayBoundary,
		retained_end: StreamLength,
		fresh_source_length: StreamLength,
		consumed_runs: NonZeroU16,
	) -> Result<Self, WitnessedPassBudgetError> {
		if boundary.head.sequence() == 0 || boundary.offset < overhead()? {
			return Err(Error::Boundary);
		}
		if boundary.offset > MAX_FIRST_SEGMENT_BYTES {
			return Err(Error::SegmentLimit);
		}
		if usize::from(consumed_runs.get()) >= MAX_REMOTE_REPLAY_ATTEMPTS {
			return Err(Error::RunLimit);
		}
		let new_run = consumed_runs.checked_add(1).ok_or(Error::RunLimit)?;
		let suffix = fresh_source_length
			.get()
			.checked_sub(retained_end.get())
			.ok_or(Error::SourceExtent)?;
		let checkpoint_count = u16::try_from(suffix.div_ceil(MAX_REMOTE_CHECKPOINT_BYTES))
			.ok()
			.filter(|&count| count <= MAX_REMOTE_CHECKPOINTS)
			.ok_or(Error::CheckpointLimit)?;
		let journal = Capacity::frame(MAX_REMOTE_CONTINUATION_PAYLOAD_BYTES)?
			.plus(Capacity::checkpoints(checkpoint_count)?)?
			.plus(phase::initial(fresh_available(new_run))?)?;
		let reserved_end = boundary
			.offset
			.checked_add(journal.bytes)
			.filter(|&end| end <= MAX_FIRST_SEGMENT_BYTES)
			.ok_or(Error::SegmentLimit)?;
		let reserved_sequence = boundary
			.head
			.sequence()
			.checked_add(u64::from(journal.frames))
			.ok_or(Error::SequenceLimit)?;
		Ok(Self {
			boundary,
			retained_end,
			fresh_source_length,
			checkpoint_count,
			new_run,
			reserved_end,
			reserved_frames: journal.frames,
			reserved_sequence,
		})
	}

	/// Exact accepted head and logical EOF selected before kind 40.
	pub const fn boundary(self) -> RemoteReplayBoundary {
		self.boundary
	}

	/// Exclusive end of the adopted prefix.
	pub const fn retained_end(self) -> StreamLength {
		self.retained_end
	}

	/// Independently selected logical end of the fresh source.
	pub const fn fresh_source_length(self) -> StreamLength {
		self.fresh_source_length
	}

	/// Number of scheduled positive suffix ranges.
	pub const fn checkpoint_count(self) -> u16 {
		self.checkpoint_count
	}

	/// The exclusive-ended range at a one-based planned checkpoint ordinal.
	pub fn checkpoint_range(self, ordinal: NonZeroU16) -> Option<Range<u64>> {
		if ordinal.get() > self.checkpoint_count {
			return None;
		}
		let index = u64::from(ordinal.get().checked_sub(1)?);
		let start = self
			.retained_end
			.get()
			.checked_add(index.checked_mul(MAX_REMOTE_CHECKPOINT_BYTES)?)?;
		let remaining = self.fresh_source_length.get().checked_sub(start)?;
		let end = start.checked_add(remaining.min(MAX_REMOTE_CHECKPOINT_BYTES))?;
		Some(start..end)
	}

	/// Logical ordinal this continuation would consume.
	pub const fn new_run(self) -> NonZeroU16 {
		self.new_run
	}

	/// Whether space remains for one separate logical pass after retirement.
	pub fn allows_fresh_retirement(self) -> bool {
		fresh_available(self.new_run)
	}

	/// Exclusive segment-relative byte limit needed for the whole pass.
	pub const fn reserved_end(self) -> u64 {
		self.reserved_end
	}

	/// Number of frame slots required after the exact original head.
	pub const fn reserved_frames(self) -> u16 {
		self.reserved_frames
	}

	/// Capacity required for the separate canonical receipt artifact.
	pub const fn receipt_bytes(self) -> u16 {
		MAX_REMOTE_WITNESS_RECEIPT_BYTES
	}

	/// Rechecks capacity against an independently authenticated phase boundary.
	///
	/// A caller resolves the phase, checkpoint ordinal and current head from the
	/// authenticated journal, independently compares actual held EOF and uses
	/// the planned ranges when admitting each checkpoint. This method checks
	/// position and capacity and does not authenticate a descendant digest.
	///
	/// # Errors
	/// Refuses an inconsistent position, out-of-plan progress, or insufficient
	/// remaining capacity.
	pub fn recheck_remaining(
		self,
		boundary: RemoteReplayBoundary,
		progress: WitnessedPassProgress,
	) -> Result<WitnessedPassRemaining, WitnessedPassBudgetError> {
		let (frames_used, journal) = progress.required(self)?;
		if frames_used == 0 {
			if boundary != self.boundary {
				return Err(Error::Boundary);
			}
		} else {
			let expected_sequence = self
				.boundary
				.head
				.sequence()
				.checked_add(u64::from(frames_used))
				.ok_or(Error::SequenceLimit)?;
			let min_offset = self
				.boundary
				.offset
				.checked_add(
					overhead()?
						.checked_mul(u64::from(frames_used))
						.ok_or(Error::Arithmetic)?,
				)
				.ok_or(Error::Arithmetic)?;
			if boundary.head.sequence() != expected_sequence
				|| boundary.head.digest() == self.boundary.head.digest()
				|| boundary.offset < min_offset
			{
				return Err(Error::Boundary);
			}
		}
		self.check_remaining(boundary.offset, boundary.head.sequence(), journal)
	}

	/// Projects remaining capacity after one scheduled checkpoint.
	///
	/// The current predecessor must come from independently authenticated
	/// replay. The caller supplies the exact prospective segment-relative
	/// end from the selected checkpoint encoding. No future head is assumed.
	/// Recheck the actual successor after synchronization and replay.
	///
	/// # Errors
	/// Refuses an unplanned ordinal, an inconsistent current position, a
	/// prospective frame width outside the selected bounds, or a short reserve.
	pub fn required_after_checkpoint(
		self,
		current: RemoteReplayBoundary,
		ordinal: NonZeroU16,
		checkpoint_end: u64,
	) -> Result<WitnessedPassRemaining, WitnessedPassBudgetError> {
		if ordinal.get() > self.checkpoint_count {
			return Err(Error::Progress);
		}
		let completed = ordinal.get().checked_sub(1).ok_or(Error::Progress)?;
		self.recheck_remaining(
			current,
			WitnessedPassProgress::Continued {
				completed_checkpoints: completed,
			},
		)?;
		let frame_bytes = checkpoint_end
			.checked_sub(current.offset)
			.ok_or(Error::Boundary)?;
		let framed_cap = Capacity::frame(MAX_REMOTE_CONTINUED_CHECKPOINT_BYTES)?.bytes;
		if !(overhead()?..=framed_cap).contains(&frame_bytes) {
			return Err(Error::Boundary);
		}
		let sequence = current
			.head
			.sequence()
			.checked_add(1)
			.ok_or(Error::SequenceLimit)?;
		let (_, journal) = WitnessedPassProgress::Continued {
			completed_checkpoints: ordinal.get(),
		}
		.required(self)?;
		self.check_remaining(checkpoint_end, sequence, journal)
	}

	fn check_remaining(
		self,
		offset: u64,
		sequence: u64,
		journal: Capacity,
	) -> Result<WitnessedPassRemaining, Error> {
		if offset
			.checked_add(journal.bytes)
			.is_none_or(|end| end > self.reserved_end)
			|| sequence
				.checked_add(u64::from(journal.frames))
				.is_none_or(|end| end > self.reserved_sequence)
		{
			return Err(Error::ReservationExceeded);
		}
		Ok(WitnessedPassRemaining { journal })
	}
}

fn fresh_available(run: NonZeroU16) -> bool {
	usize::from(run.get()) < MAX_REMOTE_REPLAY_ATTEMPTS
}

fn overhead() -> Result<u64, Error> {
	u64::try_from(FRAME_OVERHEAD_BYTES).map_err(|_| Error::Arithmetic)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Capacity {
	bytes: u64,
	frames: u16,
}

impl Capacity {
	fn frame(payload: usize) -> Result<Self, Error> {
		let bytes = overhead()?
			.checked_add(u64::try_from(payload).map_err(|_| Error::Arithmetic)?)
			.ok_or(Error::Arithmetic)?;
		Ok(Self { bytes, frames: 1 })
	}

	fn checkpoints(frames: u16) -> Result<Self, Error> {
		let bytes = Self::frame(MAX_REMOTE_CONTINUED_CHECKPOINT_BYTES)?
			.bytes
			.checked_mul(u64::from(frames))
			.ok_or(Error::Arithmetic)?;
		Ok(Self { bytes, frames })
	}

	fn plus(self, extra: Self) -> Result<Self, Error> {
		Ok(Self {
			bytes: self
				.bytes
				.checked_add(extra.bytes)
				.ok_or(Error::Arithmetic)?,
			frames: self
				.frames
				.checked_add(extra.frames)
				.ok_or(Error::Arithmetic)?,
		})
	}

	fn max(self, other: Self) -> Self {
		Self {
			bytes: self.bytes.max(other.bytes),
			frames: self.frames.max(other.frames),
		}
	}
}
