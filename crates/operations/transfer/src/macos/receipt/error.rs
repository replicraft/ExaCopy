use std::fmt;

use exacopy_endpoint::NameError;
use exacopy_journal::DarwinPhaseError;

/// A managed APFS receipt artifact or journal association failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DarwinCopyReceiptError {
	/// The artifact exceeds the receipt size limit.
	TooLarge,
	/// A field has an unexpected CBOR type, shape, or length.
	InvalidCbor,
	/// The artifact uses nonminimal encodings or has trailing bytes.
	NonCanonical,
	/// The receipt version or required features are unsupported.
	UnsupportedVersion,
	/// The observation profile or achieved durability value is unsupported.
	UnsupportedProfile,
	/// The recorded job or root capability identifier is invalid.
	InvalidBinding,
	/// The recorded component is not an admitted Unix name.
	InvalidTarget(NameError),
	/// A native identity is invalid or conflicts with a required distinct identity.
	IdentityMismatch,
	/// The verified stream length is outside the admitted extent.
	InvalidLength,
	/// Required metadata is outside the fixed managed APFS policy.
	InvalidMetadata,
	/// The kind-9 frame does not match the expected reference or synchronization profile.
	InvalidDurabilityFrame,
	/// The supplied plan, receipt and journal observations do not agree.
	BindingMismatch,
	/// The publication journal evidence is malformed or inconsistent.
	Journal(DarwinPhaseError),
}

impl From<minicbor::decode::Error> for DarwinCopyReceiptError {
	fn from(_: minicbor::decode::Error) -> Self {
		Self::InvalidCbor
	}
}

impl From<DarwinPhaseError> for DarwinCopyReceiptError {
	fn from(cause: DarwinPhaseError) -> Self {
		Self::Journal(cause)
	}
}

impl fmt::Display for DarwinCopyReceiptError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::TooLarge => formatter.write_str("APFS receipt exceeds the artifact limit"),
			Self::InvalidCbor => formatter.write_str("invalid APFS receipt CBOR fields"),
			Self::NonCanonical => formatter.write_str("APFS receipt CBOR is not canonical"),
			Self::UnsupportedVersion => {
				formatter.write_str("unsupported APFS receipt version or features")
			}
			Self::UnsupportedProfile => formatter.write_str("unsupported APFS receipt profile"),
			Self::InvalidBinding => {
				formatter.write_str("invalid APFS receipt job or root identity")
			}
			Self::InvalidTarget(cause) => {
				write!(formatter, "invalid APFS receipt target ({cause})")
			}
			Self::IdentityMismatch => formatter.write_str("invalid or conflicting APFS identities"),
			Self::InvalidLength => {
				formatter.write_str("APFS receipt stream exceeds the extent limit")
			}
			Self::InvalidMetadata => formatter.write_str("invalid required APFS receipt metadata"),
			Self::InvalidDurabilityFrame => formatter.write_str("invalid APFS durability frame"),
			Self::BindingMismatch => formatter.write_str("APFS receipt evidence binding mismatch"),
			Self::Journal(cause) => {
				write!(formatter, "invalid APFS publication evidence ({cause})")
			}
		}
	}
}

impl std::error::Error for DarwinCopyReceiptError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::InvalidTarget(cause) => Some(cause),
			Self::Journal(cause) => Some(cause),
			_ => None,
		}
	}
}
