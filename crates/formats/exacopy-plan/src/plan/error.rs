use core::fmt;

use crate::document::DocumentError;

/// A rejected canonical public Plan body.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum PlanError {
	/// The input exceeds the profile's total byte limit.
	Size,
	/// Required CBOR fields have invalid types or structure.
	Malformed,
	/// The canonical Plan body version is unsupported.
	Version,
	/// A requested feature, code, or extension is unsupported.
	Unsupported,
	/// A count, text, identity atom, timestamp fraction, or I/O value exceeds its bound.
	Bounds,
	/// A UUID fails its registered role.
	Identifier,
	/// An entry page reference has the wrong kind or invalid values.
	PageReference,
	/// The advertised parent-page item counts disagree with the body total.
	CountMismatch,
	/// Bytes are not the exact canonical representation.
	NonCanonical,
	/// The supplied expected digest does not match the body bytes.
	Integrity,
}

impl fmt::Display for PlanError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Size => "plan exceeds the encoded byte limit",
			Self::Malformed => "plan has malformed required fields",
			Self::Version => "unsupported canonical plan body version",
			Self::Unsupported => "plan uses an unsupported representation",
			Self::Bounds => "plan exceeds a field limit",
			Self::Identifier => "plan has an invalid identifier",
			Self::PageReference => "plan has an invalid entry page reference",
			Self::CountMismatch => "plan entry count differs from referenced counts",
			Self::NonCanonical => "plan bytes are not canonical",
			Self::Integrity => "plan body digest differs from the expected digest",
		})
	}
}

impl core::error::Error for PlanError {}

impl From<minicbor::decode::Error> for PlanError {
	fn from(_: minicbor::decode::Error) -> Self {
		Self::Malformed
	}
}

impl From<DocumentError> for PlanError {
	fn from(error: DocumentError) -> Self {
		match error {
			DocumentError::Version => Self::Version,
			DocumentError::Unsupported => Self::Unsupported,
			DocumentError::Size | DocumentError::WrongKind => Self::PageReference,
			_ => Self::Malformed,
		}
	}
}
