use std::fmt;

use crate::OwnerError;
use crate::frame::{FrameReadError, FrameWriteError};

use super::WindowsBootstrapPrefix;

/// An identity or fixed role tuple cannot be represented.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WindowsBootstrapIdentityError {
	/// The GUID is not lowercase hyphenated ASCII.
	InvalidVolumeGuid,
	/// The opaque native file ID is all zero.
	ZeroFileId,
	/// The roles disagree on their volume GUID or serial.
	DifferentVolume,
	/// Two roles have the same opaque native file ID.
	DuplicateFileId,
}

impl fmt::Display for WindowsBootstrapIdentityError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let message = match self {
			Self::InvalidVolumeGuid => "Windows bootstrap volume GUID is not canonical",
			Self::ZeroFileId => "Windows bootstrap file ID is zero",
			Self::DifferentVolume => "Windows bootstrap roles disagree on volume",
			Self::DuplicateFileId => "Windows bootstrap file ID is repeated",
		};
		formatter.write_str(message)
	}
}

impl std::error::Error for WindowsBootstrapIdentityError {}

/// The selected signed owner could not be encoded or authenticated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WindowsBootstrapOwnerError {
	/// The envelope or body violated the shared owner record rules.
	Owner(OwnerError),
	/// An encoded role identity is invalid.
	Identity(WindowsBootstrapIdentityError),
	/// The owner has an unsupported fixed-name layout.
	Layout,
	/// The signed job differs from the independent job selection.
	Job,
	/// The signed or observed root differs from the independent root selection.
	Root,
	/// The signed roles differ from the observed roles.
	Roles,
}

impl fmt::Display for WindowsBootstrapOwnerError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Owner(error) => error.fmt(formatter),
			Self::Identity(error) => error.fmt(formatter),
			Self::Layout => formatter.write_str("unsupported Windows bootstrap layout"),
			Self::Job => formatter.write_str("Windows bootstrap job differs from the selection"),
			Self::Root => formatter.write_str("Windows bootstrap root differs from the selection"),
			Self::Roles => {
				formatter.write_str("Windows bootstrap roles differ from the observations")
			}
		}
	}
}

impl std::error::Error for WindowsBootstrapOwnerError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Owner(error) => Some(error),
			Self::Identity(error) => Some(error),
			_ => None,
		}
	}
}

impl From<OwnerError> for WindowsBootstrapOwnerError {
	fn from(error: OwnerError) -> Self {
		Self::Owner(error)
	}
}

impl From<WindowsBootstrapIdentityError> for WindowsBootstrapOwnerError {
	fn from(error: WindowsBootstrapIdentityError) -> Self {
		Self::Identity(error)
	}
}

/// The signer could not produce the exact owner and segment bytes.
#[derive(Debug)]
#[non_exhaustive]
pub enum WindowsBootstrapEncodeError {
	/// The owner claims or signature could not be encoded.
	Owner(WindowsBootstrapOwnerError),
	/// The prepared payload could not be framed in memory.
	Frame(FrameWriteError),
}

impl fmt::Display for WindowsBootstrapEncodeError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Owner(error) => error.fmt(formatter),
			Self::Frame(error) => error.fmt(formatter),
		}
	}
}

impl std::error::Error for WindowsBootstrapEncodeError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Owner(error) => Some(error),
			Self::Frame(error) => Some(error),
		}
	}
}

/// The supplied owner and segment did not yield historical bootstrap evidence.
#[derive(Debug)]
#[non_exhaustive]
pub enum WindowsBootstrapInspectionError {
	/// The independently selected owner claims could not be authenticated.
	Owner(WindowsBootstrapOwnerError),
	/// Logical EOF preceded the required first frame.
	MissingFirstFrame,
	/// The first frame could not be read or verified.
	FirstFrame(FrameReadError),
	/// The first frame disagreed with the authenticated prepared record.
	PreparedMismatch,
	/// A syntactically complete frame followed the validated first frame.
	ExtraFrame {
		/// The first validated boundary, available for diagnostics.
		prefix: WindowsBootstrapPrefix,
	},
	/// A suffix or I/O failure prevented a clean terminal observation.
	TerminalRead {
		/// The first validated boundary, available for diagnostics.
		prefix: WindowsBootstrapPrefix,
		/// The reason the terminal read failed.
		source: FrameReadError,
	},
}

impl WindowsBootstrapInspectionError {
	/// Returns the first verified prefix when terminal admission failed.
	#[must_use]
	pub const fn diagnostic_prefix(&self) -> Option<WindowsBootstrapPrefix> {
		match self {
			Self::ExtraFrame { prefix } | Self::TerminalRead { prefix, .. } => Some(*prefix),
			_ => None,
		}
	}
}

impl fmt::Display for WindowsBootstrapInspectionError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Owner(error) => error.fmt(formatter),
			Self::MissingFirstFrame => formatter.write_str("Windows bootstrap has no first frame"),
			Self::FirstFrame(error) => error.fmt(formatter),
			Self::PreparedMismatch => formatter
				.write_str("Windows first frame differs from the authenticated prepared record"),
			Self::ExtraFrame { .. } => {
				formatter.write_str("an extra frame follows Windows bootstrap")
			}
			Self::TerminalRead { source, .. } => source.fmt(formatter),
		}
	}
}

impl std::error::Error for WindowsBootstrapInspectionError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Owner(error) => Some(error),
			Self::FirstFrame(error) | Self::TerminalRead { source: error, .. } => Some(error),
			_ => None,
		}
	}
}
