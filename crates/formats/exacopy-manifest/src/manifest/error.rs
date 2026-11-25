use core::fmt;

/// A malformed or unsupported manifest, or an untrusted envelope digest.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ManifestError {
	/// A required field, primitive encoding, or input bound is invalid.
	Invalid(ManifestInvalid),
	/// The document requires features outside the supported single-file profile.
	Unsupported(ManifestUnsupported),
	/// The declared body digest differs from the independently computed digest.
	Integrity,
}

/// Details about invalid manifest input.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ManifestInvalid {
	/// The input exceeds the supported JSON byte limit.
	Size,
	/// The document exceeds the supported container nesting limit.
	Depth,
	/// The input has invalid JSON, unknown fields, or incompatible field types.
	Json,
	/// An identifier is not canonical non-nil UUID text.
	Identifier,
	/// A basename is not a single bounded Unix component.
	Basename,
	/// A logical length is not a bounded canonical decimal string.
	Length,
	/// A byte string is not canonical padded Base64.
	Base64,
	/// A digest is not exactly 32 bytes in lowercase hexadecimal.
	Digest,
	/// A declared enumeration value is unknown.
	Enum,
}

/// Details about unsupported manifest input.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ManifestUnsupported {
	/// The manifest version is unsupported.
	Version,
	/// The selected hash algorithm is unsupported.
	Algorithm,
	/// The manifest represents another consistency level or incomplete scope.
	Observation,
	/// The manifest has a different entry, path, file type, or stream shape.
	Shape,
	/// The manifest carries metadata, pages, errors, extensions, or a signature.
	AdditionalData,
}

impl From<ManifestInvalid> for ManifestError {
	fn from(reason: ManifestInvalid) -> Self {
		Self::Invalid(reason)
	}
}

impl From<ManifestUnsupported> for ManifestError {
	fn from(reason: ManifestUnsupported) -> Self {
		Self::Unsupported(reason)
	}
}

impl fmt::Display for ManifestError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::Invalid(ManifestInvalid::Size) => "manifest exceeds the JSON byte limit",
			Self::Invalid(ManifestInvalid::Depth) => "manifest exceeds the nesting limit",
			Self::Invalid(ManifestInvalid::Json) => "manifest has invalid JSON fields or structure",
			Self::Invalid(ManifestInvalid::Identifier) => "manifest has an invalid identifier",
			Self::Invalid(ManifestInvalid::Basename) => "manifest has an invalid Unix basename",
			Self::Invalid(ManifestInvalid::Length) => "manifest has an invalid stream length",
			Self::Invalid(ManifestInvalid::Base64) => "manifest has invalid Base64",
			Self::Invalid(ManifestInvalid::Digest) => "manifest has an invalid digest encoding",
			Self::Invalid(ManifestInvalid::Enum) => "manifest has an unknown enumeration value",
			Self::Unsupported(ManifestUnsupported::Version) => "manifest version is unsupported",
			Self::Unsupported(ManifestUnsupported::Algorithm) => {
				"manifest algorithm is unsupported"
			}
			Self::Unsupported(ManifestUnsupported::Observation) => {
				"manifest consistency or completeness is unsupported"
			}
			Self::Unsupported(ManifestUnsupported::Shape) => "manifest entry shape is unsupported",
			Self::Unsupported(ManifestUnsupported::AdditionalData) => {
				"manifest contains unsupported additional records"
			}
			Self::Integrity => "manifest body digest does not match",
		};
		formatter.write_str(message)
	}
}

impl core::error::Error for ManifestError {}
