use core::fmt;

use minicbor::decode;

use crate::frame::FrameKind;
use crate::{IntentError, PreparedError, VerificationRecordError};

/// Why a local publication record could not be constructed, read, or bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PublicationRecordError {
	/// A referenced frame carries a different kind.
	WrongRecordKind {
		/// Required frame kind.
		expected: FrameKind,
		/// Actual frame kind.
		actual: FrameKind,
	},
	/// A common field or native identity falls outside the local v1 shape.
	Common(PreparedError),
	/// A referenced intent payload is invalid.
	Intent(IntentError),
	/// A referenced metadata payload is invalid.
	Metadata(VerificationRecordError),
	/// A payload exceeds the local size bound.
	PayloadTooLong,
	/// A required CBOR item is incomplete.
	Truncated,
	/// A CBOR value has the wrong shape.
	InvalidCbor,
	/// Extra bytes follow the complete record.
	TrailingBytes,
	/// A CBOR value does not use its shortest form.
	NonCanonical,
	/// A state, profile, or achieved level is outside the local subset.
	UnsupportedEvidence,
	/// The frame reference uses a reserved sequence or digest.
	InvalidReference,
	/// The referenced frames do not appear in causal order.
	InvalidFrameOrder,
	/// An exact frame reference or recorded context differs from its predecessor.
	BindingMismatch,
	/// The outcome disagrees with the reported target or stage observations.
	InconsistentObservation,
	/// Directory identities do not describe distinct directories on one device.
	InvalidBarrierScope,
}

impl From<PreparedError> for PublicationRecordError {
	fn from(error: PreparedError) -> Self {
		match error {
			PreparedError::Truncated => Self::Truncated,
			PreparedError::InvalidCbor => Self::InvalidCbor,
			_ => Self::Common(error),
		}
	}
}

impl From<decode::Error> for PublicationRecordError {
	fn from(error: decode::Error) -> Self {
		if error.is_end_of_input() {
			Self::Truncated
		} else {
			Self::InvalidCbor
		}
	}
}

impl fmt::Display for PublicationRecordError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::WrongRecordKind { expected, actual } => {
				return write!(
					formatter,
					"expected journal kind {expected:?}, found {actual:?}"
				);
			}
			Self::Common(error) => {
				return write!(formatter, "invalid common journal field: {error}");
			}
			Self::Intent(error) => return write!(formatter, "invalid publication intent: {error}"),
			Self::Metadata(error) => {
				return write!(formatter, "invalid metadata evidence: {error}");
			}
			Self::PayloadTooLong => "publication observation exceeds the local record size",
			Self::Truncated => "truncated publication observation",
			Self::InvalidCbor => "invalid CBOR item in publication observation",
			Self::TrailingBytes => "trailing bytes after publication observation",
			Self::NonCanonical => "noncanonical publication observation",
			Self::UnsupportedEvidence => "unsupported publication evidence",
			Self::InvalidReference => "reserved frame sequence or digest in publication reference",
			Self::InvalidFrameOrder => "publication evidence occurs out of order",
			Self::BindingMismatch => "publication evidence does not match its predecessor",
			Self::InconsistentObservation => {
				"publication outcome disagrees with namespace observations"
			}
			Self::InvalidBarrierScope => {
				"publication barriers do not cover two distinct directories on one device"
			}
		};
		formatter.write_str(message)
	}
}

impl core::error::Error for PublicationRecordError {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			Self::Common(error) => Some(error),
			Self::Intent(error) => Some(error),
			Self::Metadata(error) => Some(error),
			_ => None,
		}
	}
}
