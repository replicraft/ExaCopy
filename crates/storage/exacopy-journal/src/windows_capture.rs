//! Authenticated historical evidence for a fresh Windows NTFS capture sibling.

mod codec;
mod error;
mod live;
mod replay;
mod selection;
mod state;

pub use error::{WindowsCaptureError, WindowsCaptureInspectionError};
pub use live::{WindowsCaptureLive, WindowsCaptureRangeObservation, append_prepared};
pub use replay::inspect;
pub use selection::{WindowsCaptureRoles, WindowsCaptureSelection};
pub use state::WindowsCapturePrefix;

use crate::frame::{FRAME_OVERHEAD_BYTES, FrameKind};

/// Maximum number of recorded capture ranges. The live stream may extend beyond these records.
pub const MAX_CAPTURE_RANGES: u16 = 4096;
/// Full capture checkpoint cadence in bytes.
pub const CAPTURE_RANGE_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum encoded preparation payload, including the signature.
pub const MAX_PREPARED_BYTES: usize = 778;
/// Exact encoded range payload, including the signature.
pub const RANGE_BYTES: usize = 180;
/// Maximum extent of the independent capture segment, including all frame envelopes.
pub const MAX_CAPTURE_SEGMENT_BYTES: usize = MAX_PREPARED_BYTES
	+ FRAME_OVERHEAD_BYTES
	+ MAX_CAPTURE_RANGES as usize * (RANGE_BYTES + FRAME_OVERHEAD_BYTES);

fn payload_limit(kind: FrameKind) -> usize {
	match kind {
		FrameKind::WindowsCapturePrepared => MAX_PREPARED_BYTES,
		FrameKind::WindowsCaptureRange => RANGE_BYTES,
		_ => 0,
	}
}
