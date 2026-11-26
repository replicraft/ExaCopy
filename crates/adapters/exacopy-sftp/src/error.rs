use std::error::Error;
use std::fmt;

use exacopy_endpoint::connection_retry::RetryError;

/// Failure of one held SFTP capture pass.
#[derive(Debug)]
#[non_exhaustive]
pub enum SftpSourceError {
	/// Capture and connection source epochs disagree.
	Epoch,
	/// The current application owner refused this connection binding.
	Binding(RetryError),
	/// The owner refused an in-flight read that also failed on the wire.
	ReadBinding {
		/// Authoritative reason the returned read could not be admitted.
		binding: RetryError,
		/// Wire failure observed during the refused read, for diagnostics.
		wire: Box<exacopy_ssh::Error>,
	},
	/// A held data-read operation timed out and its post-I/O binding was current.
	ReadTimeout,
	/// The adapter no longer holds a source for this pass.
	Closed,
	/// The observed file exceeds the destination's signed offset profile.
	Extent,
	/// The requested positive window exceeds the file or adapter limit.
	Window,
	/// The SFTP session could not confirm the operation.
	Sftp(exacopy_ssh::Error),
	/// The completed operation did not match the admitted observation or interval.
	Observation,
}

impl fmt::Display for SftpSourceError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Epoch => formatter.write_str("SFTP source epoch and connection binding disagree"),
			Self::Binding(error) => error.fmt(formatter),
			Self::ReadBinding { binding, wire } => {
				write!(
					formatter,
					"{binding}. The refused read also failed ({wire})"
				)
			}
			Self::ReadTimeout => formatter.write_str("held SFTP data read timed out"),
			Self::Closed => formatter.write_str("SFTP capture pass is closed"),
			Self::Extent => formatter.write_str("SFTP file exceeds the capture offset limit"),
			Self::Window => formatter.write_str("SFTP read window exceeds the capture bounds"),
			Self::Sftp(error) => error.fmt(formatter),
			Self::Observation => {
				formatter.write_str("SFTP operation did not match the admitted observation")
			}
		}
	}
}

impl Error for SftpSourceError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Binding(error) => Some(error),
			Self::ReadBinding { binding, .. } => Some(binding),
			Self::Sftp(error) => Some(error),
			_ => None,
		}
	}
}

impl From<exacopy_ssh::Error> for SftpSourceError {
	fn from(error: exacopy_ssh::Error) -> Self {
		Self::Sftp(error)
	}
}
