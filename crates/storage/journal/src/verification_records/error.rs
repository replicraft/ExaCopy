use core::fmt;

use minicbor::decode;

use crate::frame::FrameKind;
use crate::prepared::PreparedError;

/// Why a local sealed-stage observation could not be constructed or read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VerificationRecordError {
	/// The envelope discriminator identifies a different record.
	WrongRecordKind {
		/// Record kind required by the decoder.
		expected: FrameKind,
		/// Record kind present on the envelope.
		actual: FrameKind,
	},
	/// A common journal field or native identity does not match the local profile.
	Common(PreparedError),
	/// The payload exceeds the bounded local record size.
	PayloadTooLong,
	/// The payload ends before a required CBOR item is complete.
	Truncated,
	/// A CBOR item has an invalid type or shape for the selected record.
	InvalidCbor,
	/// One complete record is followed by additional bytes.
	TrailingBytes,
	/// A value uses a wider representation than deterministic CBOR requires.
	NonCanonical,
	/// A stream exceeds the signed local file extent limit.
	UnsupportedLength,
	/// The sealed stage body repeats an epoch different from the record header.
	EpochMismatch,
	/// A required method, barrier or metadata scope is outside the local profile.
	UnsupportedEvidence,
	/// The observed source and stage identify the same native file.
	AliasedIdentity,
	/// The two observations do not describe identical stream lengths and digests.
	MismatchedStreams,
	/// Only ordinary permissions are admitted by the local metadata profile.
	UnsupportedMode,
	/// A user or group identifier lies outside the u32 native field width.
	InvalidPrincipal,
	/// A timestamp fraction is outside the nanosecond range.
	InvalidTimestamp,
}

impl From<PreparedError> for VerificationRecordError {
	fn from(error: PreparedError) -> Self {
		match error {
			PreparedError::Truncated => Self::Truncated,
			PreparedError::InvalidCbor => Self::InvalidCbor,
			_ => Self::Common(error),
		}
	}
}

impl From<decode::Error> for VerificationRecordError {
	fn from(error: decode::Error) -> Self {
		if error.is_end_of_input() {
			Self::Truncated
		} else {
			Self::InvalidCbor
		}
	}
}

impl fmt::Display for VerificationRecordError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::WrongRecordKind { expected, actual } => {
				return write!(
					formatter,
					"expected journal kind {expected:?}, found {actual:?}"
				);
			}
			Self::Common(error) => return write!(formatter, "invalid observation field: {error}"),
			Self::PayloadTooLong => "sealed-stage observation exceeds the local record size",
			Self::Truncated => "truncated sealed-stage observation",
			Self::InvalidCbor => "invalid CBOR item in sealed-stage observation",
			Self::TrailingBytes => "trailing bytes after sealed-stage observation",
			Self::NonCanonical => "noncanonical sealed-stage observation",
			Self::UnsupportedLength => "stream length exceeds the local file limit",
			Self::EpochMismatch => "sealed-stage epoch differs from the record header",
			Self::UnsupportedEvidence => "unsupported verification or metadata evidence",
			Self::AliasedIdentity => "source and stage identify the same native file",
			Self::MismatchedStreams => "observed source and stage stream evidence differs",
			Self::UnsupportedMode => "metadata mode includes bits outside ordinary permissions",
			Self::InvalidPrincipal => {
				"metadata user or group identifier exceeds the native field width"
			}
			Self::InvalidTimestamp => "metadata timestamp nanoseconds are out of range",
		};
		formatter.write_str(message)
	}
}

impl core::error::Error for VerificationRecordError {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			Self::Common(error) => Some(error),
			_ => None,
		}
	}
}
