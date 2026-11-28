use std::{error, fmt, io};

use crate::DurableJournalError;
use crate::frame::FrameReadError;

use super::WindowsCapturePrefix;

/// The selected capture dialect could not admit the next evidence.
#[derive(Debug)]
#[non_exhaustive]
pub enum WindowsCaptureError {
	/// Independent selection or observed extent violates the bounded profile.
	Selection,
	/// Native role identities differ from the selection or overlap the original roles.
	Roles,
	/// Payload length, version or canonical binding differs from the accepted context.
	Payload,
	/// Signature or signing key does not match the original bootstrap verifier.
	Signature,
	/// The envelope kind or sequence cannot follow the accepted history.
	FrameBinding,
	/// No range is due, or the supplied range does not describe its exact end.
	Range,
	/// The initially transferred durable writer does not own an empty new boundary.
	Boundary,
	/// The transferred adapter declares a different file barrier.
	Barrier,
	/// Append, barrier or physical readback did not establish the next boundary.
	Durable(DurableJournalError),
	/// The frame was unavailable or failed envelope checks.
	Read(FrameReadError),
	/// The terminal EOF probe failed.
	Terminal(io::Error),
	/// Bytes follow the last admissible frame.
	TrailingData,
	/// EOF preceded the required preparation frame.
	MissingPreparation,
}

impl fmt::Display for WindowsCaptureError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Selection => formatter.write_str("Windows capture selection refused"),
			Self::Roles => formatter.write_str("Windows capture role identities refused"),
			Self::Payload => formatter.write_str("invalid Windows capture payload"),
			Self::Signature => formatter.write_str("Windows capture signature or signer mismatch"),
			Self::FrameBinding => formatter.write_str("Windows capture envelope binding mismatch"),
			Self::Range => formatter.write_str("Windows capture range is not due at this end"),
			Self::Boundary => formatter.write_str("Windows capture requires an empty new writer"),
			Self::Barrier => {
				formatter.write_str("Windows capture requires full file synchronization")
			}
			Self::Durable(source) => write!(formatter, "Windows capture journal: {source}"),
			Self::Read(source) => write!(formatter, "Windows capture frame: {source}"),
			Self::Terminal(source) => write!(formatter, "Windows capture EOF probe: {source}"),
			Self::TrailingData => {
				formatter.write_str("data follows the last admissible capture frame")
			}
			Self::MissingPreparation => formatter.write_str("missing Windows capture preparation"),
		}
	}
}

impl error::Error for WindowsCaptureError {
	fn source(&self) -> Option<&(dyn error::Error + 'static)> {
		match self {
			Self::Durable(source) => Some(source),
			Self::Read(source) => Some(source),
			Self::Terminal(source) => Some(source),
			_ => None,
		}
	}
}

/// A capture history ended without clean logical EOF.
/// Its optional prefix stops at the last authenticated record before the failure.
#[derive(Debug)]
pub struct WindowsCaptureInspectionError {
	/// Last authenticated prefix, if the preparation was accepted.
	pub prefix: Option<WindowsCapturePrefix>,
	/// Reason no complete inspection result was returned.
	pub source: WindowsCaptureError,
}

impl fmt::Display for WindowsCaptureInspectionError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			formatter,
			"Windows capture inspection refused: {}",
			self.source
		)
	}
}

impl error::Error for WindowsCaptureInspectionError {
	fn source(&self) -> Option<&(dyn error::Error + 'static)> {
		Some(&self.source)
	}
}
