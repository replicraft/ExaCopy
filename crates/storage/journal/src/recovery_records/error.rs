use core::fmt;

use minicbor::decode;

use crate::frame::FrameKind;
use crate::{IntentError, PreparedError, VerificationRecordError};

/// Why a local recovery record could not be constructed, decoded or bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RecoveryRecordError {
	/// The expected and actual envelope kinds differ.
	WrongRecordKind {
		/// The required kind.
		expected: FrameKind,
		/// The observed kind.
		actual: FrameKind,
	},
	/// A common payload field or Linux identity is invalid.
	Common(PreparedError),
	/// The referenced publication intent is invalid.
	Intent(IntentError),
	/// A measured extent or referenced verification or metadata record is invalid.
	Verification(VerificationRecordError),
	/// The payload exceeds the local size limit.
	PayloadTooLong,
	/// The payload ends before all required fields.
	Truncated,
	/// The payload has an unexpected CBOR shape or key.
	InvalidCbor,
	/// The payload uses noncanonical CBOR representations.
	NonCanonical,
	/// Bytes follow the last required field.
	TrailingBytes,
	/// The decision or observation code falls outside the local profile.
	UnsupportedEvidence,
	/// A frame reference uses a reserved sequence or digest.
	InvalidReference,
	/// Frame references are out of order or the exact predecessor differs.
	InvalidFrameOrder,
	/// The recovery epoch is not the next generation after the previous journal epoch.
	InvalidEpoch,
	/// Evidence disagrees with its independently supplied context or exact frame reference.
	BindingMismatch,
	/// The file and directory identities fail the identity scope checks.
	InvalidIdentityScope,
	/// The retained-stage effect sequence is zero or fails to succeed the prior effect.
	InvalidEffectSequence,
}

impl From<PreparedError> for RecoveryRecordError {
	fn from(error: PreparedError) -> Self {
		match error {
			PreparedError::Truncated => Self::Truncated,
			PreparedError::InvalidCbor => Self::InvalidCbor,
			_ => Self::Common(error),
		}
	}
}

impl From<decode::Error> for RecoveryRecordError {
	fn from(error: decode::Error) -> Self {
		if error.is_end_of_input() {
			Self::Truncated
		} else {
			Self::InvalidCbor
		}
	}
}

impl fmt::Display for RecoveryRecordError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::WrongRecordKind { expected, actual } => {
				return write!(
					formatter,
					"expected journal kind {expected:?}, found {actual:?}"
				);
			}
			Self::Common(error) => {
				return write!(formatter, "invalid common recovery field: {error}");
			}
			Self::Intent(error) => {
				return write!(formatter, "invalid original publication intent: {error}");
			}
			Self::Verification(error) => {
				return write!(formatter, "invalid recovery verification evidence: {error}");
			}
			Self::PayloadTooLong => "recovery payload exceeds the local record size",
			Self::Truncated => "truncated recovery payload",
			Self::InvalidCbor => "invalid CBOR item in recovery payload",
			Self::NonCanonical => "noncanonical recovery payload",
			Self::TrailingBytes => "trailing bytes after recovery payload",
			Self::UnsupportedEvidence => "unsupported recovery evidence",
			Self::InvalidReference => "reserved frame sequence or digest in recovery reference",
			Self::InvalidFrameOrder => {
				"recovery evidence is out of order or from a different predecessor"
			}
			Self::InvalidEpoch => "recovery epoch does not immediately succeed the prior epoch",
			Self::BindingMismatch => "recovery evidence differs from the supplied frame or context",
			Self::InvalidEffectSequence => {
				"retained publication effect sequence does not succeed the prior effect"
			}
			Self::InvalidIdentityScope => {
				"recovery identities must be distinct and reside on one device"
			}
		};
		formatter.write_str(message)
	}
}

impl core::error::Error for RecoveryRecordError {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			Self::Common(error) => Some(error),
			Self::Intent(error) => Some(error),
			Self::Verification(error) => Some(error),
			_ => None,
		}
	}
}
