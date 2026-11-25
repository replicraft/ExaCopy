use std::fmt;

use crate::frame::FrameKind;
use crate::{DarwinPreparedError, PreparedError};

/// Managed APFS phase evidence could not be decoded or associated with its prerequisites.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DarwinPhaseError {
	/// The canonical phase body exceeds the profile's limit.
	PayloadTooLong,
	/// The CBOR shape, field size, or type is invalid.
	InvalidCbor,
	/// The phase uses an unsupported profile, field, or required feature.
	Profile(PreparedError),
	/// The supplied entry preparation is invalid.
	Preparation(DarwinPreparedError),
	/// The payload includes bytes after the phase's last field.
	TrailingBytes,
	/// The payload differs from the unique canonical encoding.
	NonCanonical,
	/// The frame has a different discriminator.
	WrongKind {
		/// The expected discriminator.
		expected: FrameKind,
		/// The envelope's discriminator.
		actual: FrameKind,
	},
	/// A required barrier, read-back method, metadata result, or operation is unsupported.
	UnsupportedEvidence,
	/// A current native observation does not match the bound identity.
	IdentityMismatch,
	/// Distinct roles refer to the same native inode and volume.
	AliasedIdentity,
	/// Stage and target directories must be on the stage's volume.
	VolumeMismatch,
	/// Independently measured logical stream lengths or digests do not agree.
	StreamMismatch,
	/// The exact job, entry, epoch, owner, stage, or preceding record differs.
	BindingMismatch,
	/// Recorded required metadata is unsupported or differs from the captured source.
	MetadataMismatch,
	/// The effect sequence must be nonzero.
	InvalidEffectSequence,
	/// A frame reference uses a reserved sequence or digest.
	InvalidReference,
	/// A referenced frame occurs at or after the record that depends on it.
	InvalidFrameOrder,
	/// The outcome disagrees with the observed target or private stage name.
	InconsistentObservation,
	/// The public target is not a valid raw Unix filename component.
	InvalidComponent,
}

impl From<PreparedError> for DarwinPhaseError {
	fn from(error: PreparedError) -> Self {
		Self::Profile(error)
	}
}

impl From<DarwinPreparedError> for DarwinPhaseError {
	fn from(error: DarwinPreparedError) -> Self {
		Self::Preparation(error)
	}
}

impl From<minicbor::decode::Error> for DarwinPhaseError {
	fn from(_: minicbor::decode::Error) -> Self {
		Self::InvalidCbor
	}
}

impl fmt::Display for DarwinPhaseError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::PayloadTooLong => "managed APFS phase payload exceeds its bound",
			Self::InvalidCbor => "invalid managed APFS phase CBOR",
			Self::Profile(error) => return error.fmt(formatter),
			Self::Preparation(error) => return error.fmt(formatter),
			Self::TrailingBytes => "managed APFS phase payload has trailing bytes",
			Self::NonCanonical => "managed APFS phase payload is not deterministic CBOR",
			Self::WrongKind { expected, actual } => {
				return write!(
					formatter,
					"expected journal frame kind {expected:?}, got {actual:?}"
				);
			}
			Self::UnsupportedEvidence => "unsupported managed APFS phase evidence",
			Self::IdentityMismatch => "managed APFS phase native identity differs",
			Self::AliasedIdentity => "managed APFS phase roles alias the same native inode",
			Self::VolumeMismatch => "managed APFS publication crosses native volumes",
			Self::StreamMismatch => "managed APFS stream lengths or read-back digests differ",
			Self::BindingMismatch => "managed APFS phase prerequisite binding differs",
			Self::MetadataMismatch => "managed APFS required metadata is unsupported or differs",
			Self::InvalidEffectSequence => "managed APFS publication sequence is zero",
			Self::InvalidReference => "managed APFS evidence uses a reserved frame reference",
			Self::InvalidFrameOrder => "managed APFS publication frames are out of order",
			Self::InconsistentObservation => {
				"managed APFS outcome disagrees with namespace observations"
			}
			Self::InvalidComponent => "invalid managed APFS publication filename component",
		};
		formatter.write_str(message)
	}
}

impl std::error::Error for DarwinPhaseError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Profile(error) => Some(error),
			Self::Preparation(error) => Some(error),
			_ => None,
		}
	}
}
