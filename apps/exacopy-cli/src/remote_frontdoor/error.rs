use std::{error::Error, fmt};

use exacopy_journal::remote_download::RemoteDownloadError;
use exacopy_platform::ProtectedSnapshotError;
use exacopy_ssh::KnownHostsError;

#[derive(Debug)]
pub(crate) enum FrontdoorError {
	Operand,
	RemotePath,
	SignedSource(RemoteDownloadError),
	Destination,
	MetadataSelector,
	MetadataRequired,
	ProfilePath,
	ProfileSize,
	ProfileBounds,
	ProfileSyntax,
	Authority,
	CredentialReference,
	Route,
	Protected(ProtectedSnapshotError),
	Trust(KnownHostsError),
}

impl fmt::Display for FrontdoorError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Self::Operand => "invalid SSH authority or remote operand",
			Self::RemotePath => "expected a bounded SFTP file path with ordinary components",
			Self::SignedSource(_) => "the selected rooted SFTP source or route was refused",
			Self::Destination => "expected a local destination with a valid file name",
			Self::MetadataSelector => "unknown remote metadata policy",
			Self::MetadataRequired => {
				"ordinary SFTP requires explicit --metadata sftp-data-only-v1"
			}
			Self::ProfilePath => {
				"expected the owner profile and an absolute protected SSH profile path"
			}
			Self::ProfileSize => "protected SSH profile exceeds its byte limit",
			Self::ProfileBounds => "protected SSH extent or grant duration exceeds its limit",
			Self::ProfileSyntax => "invalid protected SSH profile schema",
			Self::Authority => "remote authority does not match the protected SSH profile",
			Self::CredentialReference => "invalid protected SSH credential reference",
			Self::Route => "invalid selected SSH route",
			Self::Protected(_) => "protected SSH configuration could not be read",
			Self::Trust(_) => "protected SSH known-hosts data was refused",
		})
	}
}

impl Error for FrontdoorError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::SignedSource(error) => Some(error),
			Self::Protected(error) => Some(error),
			Self::Trust(error) => Some(error),
			_ => None,
		}
	}
}
