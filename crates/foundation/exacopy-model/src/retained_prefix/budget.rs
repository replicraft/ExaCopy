use core::num::NonZeroU64;

use super::Live;

const MAX_CHECKPOINT_ORDINAL: u16 = 4096;

const MAX_JOURNAL_END: u64 = 64 * 1024 * 1024;

/// Exact committed journal boundary identity, including its position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
	/// Exact chain-frame digest.
	pub digest: [u8; 32],
	/// Accepted sequence of the frame.
	pub sequence: u64,
	/// Exclusive byte end within the first segment.
	pub end: u64,
}

impl Head {
	pub(super) fn is_successor_of(self, previous: Self) -> bool {
		previous.sequence.checked_add(1) == Some(self.sequence)
			&& previous.end > 0
			&& self.end > previous.end
			&& self.end <= MAX_JOURNAL_END
			&& self.digest != previous.digest
			&& self.digest != [0; 32]
	}
}

/// Storage-owner capacity evidence for a specific next write and its closeout.
///
/// Before offering these facts, the serialized caller must compute the exact
/// canonical checkpoint frame size, conservative byte and frame capacity for
/// all subsequent finalization records, and the external protected receipt
/// capacity. The model verifies matching scope and arithmetic. The caller
/// retains the native permit and storage reservations under the same lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetReservation {
	/// Exact rechecked head, source, stage and lease at permit issuance.
	pub live: Live,
	/// Exclusive end of this tail increment.
	pub tail_end: u64,
	/// Exact segment end after the canonical checkpoint.
	pub checkpoint_end: u64,
	/// Segment bytes required after that checkpoint for finalization.
	pub closing_bytes: NonZeroU64,
	/// Sequence positions required after the checkpoint for finalization.
	pub closing_frames: NonZeroU64,
	/// Total protected receipt bytes required.
	pub receipt_bytes: NonZeroU64,
	/// Receipt capacity retained for this admission.
	pub receipt_capacity: u64,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ReservedCheckpoint {
	pub(super) ordinal: u16,
	pub(super) end: u64,
}

impl BudgetReservation {
	pub(super) fn reserve(
		self,
		live: Live,
		tail_end: u64,
		ordinal: u16,
	) -> Option<ReservedCheckpoint> {
		let ordinal = ordinal.checked_add(1)?;
		let closing_end = self.checkpoint_end.checked_add(self.closing_bytes.get())?;
		live.head
			.sequence
			.checked_add(1)?
			.checked_add(self.closing_frames.get())?;
		(self.live == live
			&& self.tail_end == tail_end
			&& self.checkpoint_end > live.head.end
			&& closing_end <= MAX_JOURNAL_END
			&& ordinal <= MAX_CHECKPOINT_ORDINAL
			&& self.receipt_bytes.get() <= self.receipt_capacity)
			.then_some(ReservedCheckpoint {
				ordinal,
				end: self.checkpoint_end,
			})
	}
}
