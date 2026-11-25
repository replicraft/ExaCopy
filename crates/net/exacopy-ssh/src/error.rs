use exacopy_endpoint::ssh_sftp::{CredentialRefusal, HostKeyRefusal, SftpVersionError};
use russh_sftp::protocol::StatusCode;

/// A refusal or incomplete operation in the read-only SFTP profile.
#[derive(Debug)]
pub enum Error {
	/// The peer's host key was refused before authentication.
	HostKey(HostKeyRefusal),
	/// This pinned profile has no certificate trust policy.
	HostCertificate,
	/// The server does not support strict key exchange.
	KeyExchange,
	/// The pinned client cannot revalidate the key during rekey.
	Rekey,
	/// Credential selection failed.
	Credential(CredentialRefusal),
	/// The broker did not provide a usable password.
	Password,
	/// The key library could not construct the supplied Ed25519 key.
	Key(russh::keys::ssh_key::Error),
	/// The server rejected password authentication.
	Authentication,
	/// The server rejected the selected Ed25519 key.
	KeyAuthentication,
	/// The server did not confirm the SFTP subsystem request.
	Subsystem,
	/// The SSH peer tried to open a channel not granted by this profile.
	UnsolicitedChannel,
	/// Transport failure in SSH.
	Ssh(russh::Error),
	/// Transport failure in the SFTP stream.
	Io(std::io::Error),
	/// A supported protocol response could not be decoded or checked.
	Protocol,
	/// Peer returned a non-success status. Server text is omitted.
	Status(StatusCode),
	/// The peer selected an unsupported version.
	Version(SftpVersionError),
	/// The operation timed out and its session was fenced.
	Timeout,
	/// The session has been fenced after failure or cancellation.
	Closed,
	/// A path, size, or operation exceeded the admitted bounds.
	Limit,
	/// A source observation changed during the operation.
	Changed,
	/// The requested source is outside the regular-file profile.
	UnsupportedSource,
}

impl std::fmt::Display for Error {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::HostKey(error) => return error.fmt(formatter),
			Self::Credential(error) => return error.fmt(formatter),
			Self::Version(error) => return error.fmt(formatter),
			_ => {}
		}
		formatter.write_str(match self {
			Self::HostCertificate => "SSH host certificates are unsupported in this profile",
			Self::KeyExchange => "SSH peer does not support strict key exchange",
			Self::Rekey => "SSH credential and stream binding cannot be revalidated during rekey",
			Self::Password => "SSH credential broker did not provide a usable password",
			Self::Key(_) => "SSH credential broker did not provide a usable Ed25519 key",
			Self::Authentication => "SSH password authentication was refused",
			Self::KeyAuthentication => "SSH Ed25519 authentication was refused",
			Self::Subsystem => "SSH server did not confirm the SFTP subsystem",
			Self::UnsolicitedChannel => "SSH peer attempted to open an unrequested channel",
			Self::Ssh(_) => "SSH transport failed",
			Self::Io(_) => "SFTP stream failed",
			Self::Protocol => "invalid or unexpected SFTP response",
			Self::Status(_) => "SFTP server refused the request",
			Self::Timeout => "SSH or SFTP operation timed out",
			Self::Closed => "SFTP session is closed",
			Self::Limit => "SFTP operation exceeded its configured bounds",
			Self::Changed => "SFTP source observation changed",
			Self::UnsupportedSource => "SFTP source is outside the supported regular-file profile",
			Self::HostKey(_) | Self::Credential(_) | Self::Version(_) => unreachable!(),
		})
	}
}

impl std::error::Error for Error {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::HostKey(error) => Some(error),
			Self::Credential(error) => Some(error),
			Self::Version(error) => Some(error),
			Self::Key(error) => Some(error),
			Self::Ssh(error) => Some(error),
			Self::Io(error) => Some(error),
			_ => None,
		}
	}
}

impl From<russh::Error> for Error {
	fn from(error: russh::Error) -> Self {
		Self::Ssh(error)
	}
}

impl From<std::io::Error> for Error {
	fn from(error: std::io::Error) -> Self {
		Self::Io(error)
	}
}
