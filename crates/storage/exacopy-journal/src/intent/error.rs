use core::fmt;

use exacopy_endpoint::NameError;
use exacopy_model::InvalidJobId;

/// The reason a journal payload could not be interpreted as a local publication intent.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum IntentError {
	/// The journal envelope contains a different record kind.
	WrongRecordKind,
	/// The payload ends within a CBOR item.
	Truncated,
	/// An item has the wrong CBOR type or uses an unsupported encoding.
	InvalidCbor,
	/// An integer or length uses a wider CBOR encoding than necessary.
	NonCanonical,
	/// The map does not have exactly the fields supported by the local profile.
	UnexpectedMap,
	/// A map key is unknown, duplicate, missing, or out of order.
	UnexpectedKey {
		/// Next key required by the profile.
		expected: u64,
		/// Key encountered in the payload.
		actual: u64,
	},
	/// An item exceeds its size bound or has the wrong fixed length.
	Length,
	/// The format version is outside the local profile.
	UnsupportedVersion,
	/// Required features outside this profile were requested.
	UnsupportedFeatures,
	/// The journal job identifier is invalid.
	InvalidJob(InvalidJobId),
	/// The native identity belongs to an unsupported platform.
	UnsupportedPlatform,
	/// The native identity requests generation semantics outside the local profile.
	UnsupportedGeneration,
	/// The filename uses an unsupported encoding.
	UnsupportedComponentEncoding,
	/// The raw name is not a valid local Unix component.
	InvalidComponent(NameError),
	/// The publication primitive is outside the local profile.
	UnsupportedPrimitive,
	/// Additional bytes follow the one complete intent payload.
	TrailingBytes,
}

impl fmt::Display for IntentError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::WrongRecordKind => "the frame is not a publication intent",
			Self::Truncated => "truncated publication intent",
			Self::InvalidCbor => "invalid CBOR item in publication intent",
			Self::NonCanonical => "nonminimal CBOR item in publication intent",
			Self::UnexpectedMap => "unsupported publication intent map shape",
			Self::UnexpectedKey { expected, actual } => {
				return write!(formatter, "expected intent key {expected}, found {actual}");
			}
			Self::Length => "invalid publication intent item length",
			Self::UnsupportedVersion => "unsupported publication intent version",
			Self::UnsupportedFeatures => "unsupported required publication intent features",
			Self::InvalidJob(source) => return source.fmt(formatter),
			Self::UnsupportedPlatform => "unsupported publication intent platform",
			Self::UnsupportedGeneration => "unsupported native identity generation",
			Self::UnsupportedComponentEncoding => "unsupported publication component encoding",
			Self::InvalidComponent(source) => return source.fmt(formatter),
			Self::UnsupportedPrimitive => "unsupported exclusive publication primitive",
			Self::TrailingBytes => "trailing bytes after publication intent",
		};
		formatter.write_str(message)
	}
}

impl core::error::Error for IntentError {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			Self::InvalidJob(source) => Some(source),
			Self::InvalidComponent(source) => Some(source),
			_ => None,
		}
	}
}
