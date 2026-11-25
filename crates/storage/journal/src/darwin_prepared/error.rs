use core::fmt;

use exacopy_endpoint::NameError;

use crate::PreparedError;

/// A structurally invalid or inconsistent managed APFS preparation record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DarwinPreparedError {
	/// The frame kind or payload is invalid for the selected codec.
	Payload(PreparedError),
	/// The authenticated owner differs from the journal job, plan, or exact owner digest.
	OwnerMismatch,
	/// The entry's job, plan, epoch, owner digest, or destination root differs from the job record.
	JobMismatch,
	/// An observation identifies a different volume from its required root.
	VolumeMismatch,
	/// The source and destination have conflicting observations for a single root.
	RootBindingMismatch,
	/// Distinct observation roles identify the same native object.
	IdentityAlias,
	/// A raw source, stage, or target component is invalid.
	InvalidComponent(NameError),
}

impl fmt::Display for DarwinPreparedError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::Payload(error) => return fmt::Display::fmt(error, formatter),
			Self::InvalidComponent(error) => return fmt::Display::fmt(error, formatter),
			Self::OwnerMismatch => "Darwin preparation does not match its signed owner record",
			Self::JobMismatch => "Darwin entry preparation does not match its job preparation",
			Self::VolumeMismatch => "Darwin preparation object is outside its root volume",
			Self::RootBindingMismatch => "Darwin preparation has conflicting root observations",
			Self::IdentityAlias => "Darwin preparation roles alias the same native object",
		};
		formatter.write_str(message)
	}
}

impl core::error::Error for DarwinPreparedError {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			Self::Payload(error) => Some(error),
			Self::InvalidComponent(error) => Some(error),
			_ => None,
		}
	}
}

impl From<PreparedError> for DarwinPreparedError {
	fn from(error: PreparedError) -> Self {
		Self::Payload(error)
	}
}

impl From<minicbor::decode::Error> for DarwinPreparedError {
	fn from(error: minicbor::decode::Error) -> Self {
		PreparedError::from(error).into()
	}
}
