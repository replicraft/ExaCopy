use core::fmt;

use exacopy_endpoint::NameError;

use crate::IntentError;

/// A malformed or unsupported local journal observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PreparedError {
	/// The envelope discriminator does not match the requested record.
	WrongRecordKind,
	/// The encoded payload exceeds the local profile bound.
	PayloadTooLarge,
	/// Input ended within the expected record.
	Truncated,
	/// A CBOR item has an unexpected value type, shape, field number or width.
	InvalidCbor,
	/// The record contains trailing data or a noncanonical CBOR representation.
	NonCanonical,
	/// The record requires an unsupported format version.
	UnsupportedVersion,
	/// The record requires unsupported features.
	UnsupportedFeatures,
	/// The payload failed UUIDv7 job validation.
	InvalidJob(IntentError),
	/// The root capability ID is outside the supported UUID profile.
	InvalidRoot,
	/// The plan reference differs from the common plan digest.
	PlanMismatch,
	/// The record includes an unsupported native identity representation.
	UnsupportedIdentity,
	/// The record requests unsupported source consistency semantics.
	UnsupportedSourceView,
	/// The observed source length exceeded the format maximum.
	InvalidSourceLength,
	/// The observed timestamp's fraction is at least a full second.
	InvalidTimestamp,
	/// Source mode includes bits outside Linux permission and special bits.
	InvalidMode,
	/// The record includes an unsupported source metadata observation.
	UnsupportedSourceMetadata,
	/// The stage and source observations identify the same native object.
	SourceStageAlias,
	/// The target path uses an unsupported component encoding.
	UnsupportedTargetEncoding,
	/// The target component is invalid for the local Unix profile.
	InvalidTargetComponent(NameError),
	/// The record includes an unsupported target metadata observation.
	UnsupportedTargetObservation,
}

impl fmt::Display for PreparedError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::WrongRecordKind => "unexpected journal record kind",
			Self::PayloadTooLarge => "journal observation exceeds its payload bound",
			Self::Truncated => "truncated journal observation",
			Self::InvalidCbor => "invalid journal observation CBOR item",
			Self::NonCanonical => "noncanonical journal observation payload",
			Self::UnsupportedVersion => "unsupported journal observation version",
			Self::UnsupportedFeatures => "unsupported required journal observation features",
			Self::InvalidJob(error) => return fmt::Display::fmt(error, formatter),
			Self::InvalidRoot => "invalid root capability UUID",
			Self::PlanMismatch => "journal plan reference differs from the common plan digest",
			Self::UnsupportedIdentity => "unsupported journal native identity",
			Self::UnsupportedSourceView => "unsupported source consistency observation",
			Self::InvalidSourceLength => "source length exceeds the local observation bound",
			Self::InvalidTimestamp => "invalid source timestamp fraction",
			Self::InvalidMode => "invalid Linux source mode bits",
			Self::UnsupportedSourceMetadata => "unsupported source metadata observation",
			Self::SourceStageAlias => "source and stage observations alias",
			Self::UnsupportedTargetEncoding => "unsupported target component encoding",
			Self::InvalidTargetComponent(error) => return fmt::Display::fmt(error, formatter),
			Self::UnsupportedTargetObservation => "unsupported target metadata observation",
		};
		formatter.write_str(message)
	}
}

impl core::error::Error for PreparedError {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			Self::InvalidJob(error) => Some(error),
			Self::InvalidTargetComponent(error) => Some(error),
			_ => None,
		}
	}
}

impl From<minicbor::decode::Error> for PreparedError {
	fn from(error: minicbor::decode::Error) -> Self {
		if error.is_end_of_input() {
			Self::Truncated
		} else {
			Self::InvalidCbor
		}
	}
}
