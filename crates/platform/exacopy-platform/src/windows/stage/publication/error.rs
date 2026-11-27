use std::error::Error;
use std::fmt;
use std::io;

use super::WindowsUnconfirmedPublicationDirectory;
use crate::windows::{NativeStageError, WindowsStageError, native::Refusal};

/// Refusal or incomplete evidence from the experimental publication adapter.
#[derive(Debug)]
#[non_exhaustive]
pub enum WindowsPublicationError {
	/// The exact model attempt differs from the bound logical and physical placement.
	BindingMismatch,
	/// The held destination parent lacks direct child creation rights.
	DestinationAccess,
	/// The native query could not determine the held parent rights.
	DestinationAccessQuery(i32),
	/// The requested destination directory already exists.
	DestinationOccupied,
	/// The exclusive directory creation effect could not be determined.
	DestinationCreateUncertain(NativeStageError),
	/// A returned native directory handle could not be confirmed.
	DestinationCreatedUnconfirmed {
		/// The held result and any confirmed identifying evidence.
		retained: WindowsUnconfirmedPublicationDirectory,
		/// The specific admission or observation refusal.
		cause: Box<WindowsPublicationError>,
	},
	/// The admitted directory is not on a fixed local NTFS volume.
	UnsupportedVolume,
	/// The parents are identical or do not share an exact physical volume.
	ParentScope,
	/// The held parent differs from its originally admitted identity.
	ParentChanged,
	/// A stage admission or observation failed.
	Stage(WindowsStageError),
	/// A required native metadata query did not succeed.
	MetadataQuery(io::Error),
	/// Metadata falls outside the supported unnamed-stream profile.
	UnsupportedMetadata,
	/// Observed required metadata differs from sealed metadata.
	MetadataChanged,
	/// The counted native rename buffer could not be represented.
	InvalidRenameLength,
	/// The former private name appears occupied after the rename.
	FormerNameOccupied,
	/// The destination name or held file differs from the expected file.
	TargetChanged,
}

impl WindowsPublicationError {
	pub(super) fn native(cause: Refusal) -> Self {
		Self::Stage(WindowsStageError::native(cause))
	}

	pub(super) fn destination_creation_uncertain(cause: Refusal) -> Self {
		Self::DestinationCreateUncertain(NativeStageError::new(cause))
	}
}

impl From<WindowsStageError> for WindowsPublicationError {
	fn from(cause: WindowsStageError) -> Self {
		Self::Stage(cause)
	}
}

impl fmt::Display for WindowsPublicationError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::BindingMismatch => formatter.write_str("publication binding mismatch"),
			Self::DestinationAccess => {
				formatter.write_str("destination handle lacks child creation authority")
			}
			Self::DestinationAccessQuery(cause) => {
				write!(formatter, "destination access query failed ({cause:#010x})")
			}
			Self::DestinationOccupied => {
				formatter.write_str("the destination directory already exists")
			}
			Self::DestinationCreateUncertain(cause) => write!(
				formatter,
				"destination directory creation is uncertain ({cause})"
			),
			Self::DestinationCreatedUnconfirmed { cause, .. } => write!(
				formatter,
				"the destination directory needs reconciliation ({cause})"
			),
			Self::UnsupportedVolume => formatter.write_str("publication requires fixed local NTFS"),
			Self::ParentScope => {
				formatter.write_str("publication requires distinct parents on one physical volume")
			}
			Self::ParentChanged => formatter.write_str("the held parent identity changed"),
			Self::Stage(cause) => write!(formatter, "stage observation failed ({cause})"),
			Self::MetadataQuery(cause) => {
				write!(formatter, "required metadata query failed ({cause})")
			}
			Self::UnsupportedMetadata => {
				formatter.write_str("metadata is outside the supported unnamed-stream profile")
			}
			Self::MetadataChanged => formatter.write_str("the required stage metadata changed"),
			Self::InvalidRenameLength => {
				formatter.write_str("the native rename buffer length is invalid")
			}
			Self::FormerNameOccupied => formatter.write_str("the former private name is occupied"),
			Self::TargetChanged => {
				formatter.write_str("the published file identity or stamp changed")
			}
		}
	}
}

impl Error for WindowsPublicationError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Stage(cause) => Some(cause),
			Self::DestinationCreateUncertain(cause) => Some(cause),
			Self::DestinationCreatedUnconfirmed { cause, .. } => Some(cause.as_ref()),
			Self::MetadataQuery(cause) => Some(cause),
			_ => None,
		}
	}
}
