use core::fmt;

use super::PlanError;

/// Failure to admit or produce an unsigned public Plan JSON envelope.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum PlanJsonError {
	/// Input or output exceeded the JSON profile limit.
	Size,
	/// A JSON container exceeded the profile nesting bound.
	Depth,
	/// JSON syntax, types, required fields, or collection shape were invalid.
	Json,
	/// The envelope does not select the supported schema version.
	Version,
	/// An approval field is outside the unsigned profile.
	Approval,
	/// The value is outside the supported RFC 3339 timestamp profile.
	Timestamp,
	/// The identifier is not an accepted UUID spelling.
	Identifier,
	/// The numeric string is not a canonical unsigned 64-bit decimal integer.
	Integer,
	/// The digest is not exactly 64 lowercase hexadecimal digits.
	Digest,
	/// An identity is outside the accepted canonical base64 profile.
	Base64,
	/// A required policy or reference value is unknown or unsupported.
	Unsupported,
	/// An extension cannot be represented as a bounded canonical CBOR value.
	Extension,
	/// Canonical body validation or digest comparison failed.
	Body(PlanError),
}

impl From<PlanError> for PlanJsonError {
	fn from(error: PlanError) -> Self {
		Self::Body(error)
	}
}

impl fmt::Display for PlanJsonError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::Size => "plan JSON exceeds the size limit",
			Self::Depth => "plan JSON exceeds the nesting limit",
			Self::Json => "invalid plan JSON syntax or shape",
			Self::Version => "unsupported plan JSON schema version",
			Self::Approval => "attached approval is unsupported in the unsigned plan profile",
			Self::Timestamp => "timestamp is outside the plan JSON profile",
			Self::Identifier => "invalid plan JSON UUID",
			Self::Integer => "invalid plan JSON unsigned decimal value",
			Self::Digest => "invalid plan JSON digest spelling",
			Self::Base64 => "invalid or oversized plan JSON identity atom",
			Self::Unsupported => "unsupported plan JSON enum or policy value",
			Self::Extension => "invalid or unsupported plan JSON extension",
			Self::Body(error) => return error.fmt(f),
		};
		f.write_str(message)
	}
}

impl core::error::Error for PlanJsonError {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			Self::Body(error) => Some(error),
			_ => None,
		}
	}
}
