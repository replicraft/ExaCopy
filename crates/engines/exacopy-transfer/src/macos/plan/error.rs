use std::error::Error;
use std::fmt;

use exacopy_endpoint::NameError;

/// A managed APFS copy plan outside the supported contract.
#[derive(Debug)]
#[non_exhaustive]
pub enum DarwinCopyPlanError {
	/// Serialized bytes exceed the fixed plan limit.
	PayloadTooLarge,
	/// CBOR is malformed, truncated, or has the wrong type.
	InvalidCbor(minicbor::decode::Error),
	/// A record has an unexpected array or map shape.
	InvalidShape,
	/// The version or required feature set is unsupported.
	UnsupportedVersion,
	/// The requested copy policy is unsupported.
	UnsupportedPolicy,
	/// A job UUID fails the journal's UUIDv7 contract.
	InvalidJobId,
	/// An entry identifier is not exactly 16 bytes.
	InvalidEntryId,
	/// A root identifier fails the capability UUID contract.
	InvalidRootId,
	/// A profile identifier fails the owner profile contract.
	InvalidProfileId,
	/// The plan names another local profile.
	ProfileMismatch,
	/// A raw component fails the shared endpoint name contract.
	InvalidComponent(NameError),
	/// A physical APFS identity fails the native identity contract.
	InvalidIdentity,
	/// A recorded timestamp has an invalid fractional second.
	InvalidTimestamp,
	/// The ordinary permission bits or ownership fail the strict basic policy.
	UnsupportedMetadata,
	/// The planned logical extent exceeds the adapter limit.
	SourceTooLong,
	/// The source identity differs in native volume from its root.
	SourceOutsideRootVolume,
	/// Observations conflict across the selected native objects or grants.
	ConflictingIdentities,
	/// Source and target components are identical within a shared root.
	ConflictingNames,
	/// The input differs from the canonical encoding or has trailing bytes.
	NonCanonical,
}

impl fmt::Display for DarwinCopyPlanError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidCbor(error) => write!(formatter, "invalid APFS copy plan CBOR ({error})"),
			Self::InvalidComponent(error) => write!(formatter, "invalid APFS plan name ({error})"),
			Self::PayloadTooLarge => formatter.write_str("APFS copy plan exceeds the byte limit"),
			Self::InvalidShape => formatter.write_str("invalid APFS copy plan shape"),
			Self::UnsupportedVersion => formatter.write_str("unsupported APFS copy plan version"),
			Self::UnsupportedPolicy => formatter.write_str("unsupported APFS copy plan policy"),
			Self::InvalidJobId => formatter.write_str("invalid APFS plan job identifier"),
			Self::InvalidEntryId => formatter.write_str("invalid APFS plan entry identifier"),
			Self::InvalidRootId => formatter.write_str("invalid APFS plan root identifier"),
			Self::InvalidProfileId => formatter.write_str("invalid APFS plan profile identifier"),
			Self::ProfileMismatch => formatter.write_str("APFS plan profile does not match"),
			Self::InvalidIdentity => formatter.write_str("invalid APFS plan native identity"),
			Self::InvalidTimestamp => formatter.write_str("invalid APFS plan timestamp"),
			Self::UnsupportedMetadata => formatter.write_str("unsupported APFS plan metadata"),
			Self::SourceTooLong => formatter.write_str("APFS plan extent exceeds the file limit"),
			Self::SourceOutsideRootVolume => {
				formatter.write_str("planned APFS source is outside its root volume")
			}
			Self::ConflictingIdentities => formatter.write_str("conflicting APFS plan identities"),
			Self::ConflictingNames => formatter.write_str("conflicting APFS plan names"),
			Self::NonCanonical => formatter.write_str("APFS copy plan encoding is not canonical"),
		}
	}
}

impl Error for DarwinCopyPlanError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::InvalidCbor(error) => Some(error),
			Self::InvalidComponent(error) => Some(error),
			_ => None,
		}
	}
}

impl From<minicbor::decode::Error> for DarwinCopyPlanError {
	fn from(error: minicbor::decode::Error) -> Self {
		Self::InvalidCbor(error)
	}
}
