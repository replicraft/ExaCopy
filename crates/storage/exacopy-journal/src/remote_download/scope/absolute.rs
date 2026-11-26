use exacopy_endpoint::remote_source::SftpPathRoot;
use exacopy_endpoint::ssh_sftp::SshAuthority;

use super::{Error, RemoteDownloadRoute, RemoteDownloadSource};

impl RemoteDownloadSource {
	/// Binds the exact absolute SFTP name, including its leading slash.
	/// The caller still establishes actual held source and route authority.
	/// # Errors
	/// Refuses nonabsolute names, invalid components, and unbound routes.
	pub fn new_absolute(
		authority: SshAuthority,
		host_key_sha256: [u8; 32],
		route: RemoteDownloadRoute,
		path: &[u8],
	) -> Result<Self, Error> {
		Self::new_rooted(
			authority,
			host_key_sha256,
			route,
			path,
			SftpPathRoot::Absolute,
		)
	}

	/// Returns the exact path base implied by the canonical signed bytes.
	#[must_use]
	pub fn path_root(&self) -> SftpPathRoot {
		path_root(&self.path)
	}
}

pub(super) fn path_root(path: &[u8]) -> SftpPathRoot {
	if path.first() == Some(&b'/') {
		SftpPathRoot::Absolute
	} else {
		SftpPathRoot::AccountRelative
	}
}

pub(super) fn component_bytes(path: &[u8], root: SftpPathRoot) -> Result<&[u8], Error> {
	match root {
		SftpPathRoot::AccountRelative => Ok(path),
		// The borrowed suffix is for component validation only. The signed
		// source retains the complete original bytes including the leading slash.
		SftpPathRoot::Absolute => path.strip_prefix(b"/").ok_or(Error::Scope),
	}
}
