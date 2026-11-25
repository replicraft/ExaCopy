use std::{error::Error, fmt, io};

use exacopy_endpoint::IoError;

use crate::windows::native::Refusal;
use crate::windows::read_path::PathError;

#[derive(Debug)]
pub(in crate::windows) enum ReadError {
	Path(PathError),
	RootOpen(io::Error),
	NotFixedDrive,
	NotVolumeRoot,
	Native(Refusal),
	Changed,
	Extent,
	Range,
	ReaderUnavailable,
	Read(io::Error),
	ExactRead(IoError),
}

/// An inconclusive admission, observation, or read of a Windows comparison input.
#[derive(Debug)]
pub struct WindowsReadError(pub(super) ReadError);

impl WindowsReadError {
	/// Reports whether the operand spelling is outside the literal drive path contract.
	#[must_use]
	pub const fn is_invalid_path(&self) -> bool {
		matches!(self.0, ReadError::Path(_))
	}
}

impl fmt::Display for WindowsReadError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match &self.0 {
			ReadError::Path(error) => error.fmt(formatter),
			ReadError::RootOpen(error) => write!(formatter, "could not open drive root ({error})"),
			ReadError::NotFixedDrive => {
				formatter.write_str("drive is outside the local fixed profile")
			}
			ReadError::NotVolumeRoot => {
				formatter.write_str("drive alias does not name the volume root")
			}
			ReadError::Native(error) => {
				write!(formatter, "native handle operation failed ({error})")
			}
			ReadError::Changed => formatter.write_str("held comparison input changed"),
			ReadError::Extent => formatter.write_str("file extent exceeds the comparison bounds"),
			ReadError::Range => formatter.write_str("read is outside the observed file extent"),
			ReadError::ReaderUnavailable => formatter.write_str("held reader is unavailable"),
			ReadError::Read(error) => write!(formatter, "positioned read failed ({error})"),
			ReadError::ExactRead(error) => write!(formatter, "exact read failed ({error})"),
		}
	}
}

impl Error for WindowsReadError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match &self.0 {
			ReadError::Path(error) => Some(error),
			ReadError::RootOpen(error) | ReadError::Read(error) => Some(error),
			ReadError::Native(Refusal::QueryFailed(error)) => Some(error),
			ReadError::ExactRead(error) => Some(error),
			_ => None,
		}
	}
}

impl From<ReadError> for WindowsReadError {
	fn from(error: ReadError) -> Self {
		Self(error)
	}
}

impl From<Refusal> for WindowsReadError {
	fn from(error: Refusal) -> Self {
		Self(ReadError::Native(error))
	}
}
