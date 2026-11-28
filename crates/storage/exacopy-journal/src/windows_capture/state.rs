use crate::frame::{ChainHead, FRAME_OVERHEAD_BYTES};

use super::{CAPTURE_RANGE_BYTES, MAX_CAPTURE_RANGES, RANGE_BYTES};

/// Last accepted historical record boundary and contiguous range coverage.
/// A prefix remains historical even when coverage reaches the declared extent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsCapturePrefix {
	head: ChainHead,
	segment_end: u64,
	extent: u64,
	covered: u64,
	ranges: u16,
}

impl WindowsCapturePrefix {
	/// Sequence and digest of the last authenticated record.
	#[must_use]
	pub const fn head(self) -> ChainHead {
		self.head
	}

	/// Exact segment offset after the last accepted record.
	#[must_use]
	pub const fn segment_end(self) -> u64 {
		self.segment_end
	}

	/// Signed observed source extent.
	#[must_use]
	pub const fn observed_extent(self) -> u64 {
		self.extent
	}

	/// The number of contiguous source bytes described by accepted range records.
	#[must_use]
	pub const fn covered_bytes(self) -> u64 {
		self.covered
	}

	/// Number of successfully accepted range records.
	#[must_use]
	pub const fn ranges(self) -> u16 {
		self.ranges
	}

	pub(super) const fn prepared(head: ChainHead, segment_end: u64, extent: u64) -> Self {
		Self {
			head,
			segment_end,
			extent,
			covered: 0,
			ranges: 0,
		}
	}

	pub(super) fn next_range(self) -> Option<RangePosition> {
		if self.ranges >= MAX_CAPTURE_RANGES || self.covered >= self.extent {
			return None;
		}
		Some(RangePosition {
			ordinal: self.ranges + 1,
			offset: self.covered,
			length: (self.extent - self.covered).min(CAPTURE_RANGE_BYTES),
		})
	}

	pub(super) fn advance(&mut self, head: ChainHead, position: RangePosition) {
		self.head = head;
		self.segment_end += (FRAME_OVERHEAD_BYTES + RANGE_BYTES) as u64;
		self.covered = position.end();
		self.ranges = position.ordinal;
	}
}

#[derive(Clone, Copy)]
pub(super) struct RangePosition {
	pub(super) ordinal: u16,
	pub(super) offset: u64,
	pub(super) length: u64,
}

impl RangePosition {
	pub(super) const fn end(self) -> u64 {
		self.offset + self.length
	}
}
