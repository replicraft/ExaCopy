//! Parse and admit the protected inputs to a Linux agentless SFTP download.
//!
//! The foreground coordinator still owns route effects, authentication,
//! destination admission and the transfer. These helpers create no job.

use std::ffi::OsStr;
use std::fmt;
use std::path::PathBuf;

use exacopy_journal::remote_download::finalization_policy::SftpDataOnlyV1;
use exacopy_journal::remote_download::{RemoteDownloadRoute, RemoteDownloadSource};
use exacopy_transfer::remote_metadata::{
	ApprovedSftpMetadata, RemoteMetadataSelection, admit_sftp_metadata,
};

mod error;
mod native;
mod operand;
mod profile;
mod route;
#[cfg(all(test, unix))]
mod tests;

pub(crate) use error::FrontdoorError;
pub(crate) use operand::{RemoteOperand, RemotePath};
pub(crate) use profile::SshProfile;
#[cfg(any(test, feature = "experimental-ssh-wireguard"))]
pub(crate) use route::WireGuardRoute;
pub(crate) use route::{AddressOrder, ApprovedRoute};

/// Bounded foreground inputs with explicit authority and metadata policy.
pub(crate) struct GetRequest {
	pub(crate) source: RemoteOperand,
	pub(crate) destination: PathBuf,
	pub(crate) owner_profile: PathBuf,
	pub(crate) ssh_profile: PathBuf,
	pub(crate) metadata: ApprovedSftpMetadata,
}

impl GetRequest {
	pub(crate) fn new(
		source: &OsStr,
		destination: PathBuf,
		owner_profile: PathBuf,
		ssh_profile: PathBuf,
		metadata: Option<&str>,
	) -> Result<Self, FrontdoorError> {
		let metadata = require_metadata(metadata)?;
		let source = RemoteOperand::parse(source)?;
		native::destination_path(&destination)?;
		if owner_profile.as_os_str().is_empty() {
			return Err(FrontdoorError::ProfilePath);
		}
		let ssh_profile = profile::protected_path(ssh_profile)?;
		Ok(Self {
			source,
			destination,
			owner_profile,
			ssh_profile,
			metadata,
		})
	}

	/// Creates the exact rooted source for the selected approved route.
	/// The route owner supplies the resolved literal for a resolve-authority profile.
	pub(crate) fn signed_source(
		&self,
		profile: &SshProfile,
		route: RemoteDownloadRoute,
	) -> Result<RemoteDownloadSource, FrontdoorError> {
		profile.require_source(&self.source)?;
		let approved = match (&profile.route, route) {
			(ApprovedRoute::Direct(approved), RemoteDownloadRoute::ResolvedDirect { endpoint }) => {
				*approved == endpoint
			}
			(ApprovedRoute::ResolveAuthority(_), RemoteDownloadRoute::ResolvedDirect { .. }) => {
				true
			}
			(
				ApprovedRoute::EmbeddedWireGuard(approved),
				RemoteDownloadRoute::EmbeddedWireGuard {
					peer,
					revision,
					inner,
				},
			) => {
				approved.peer_public_key == peer
					&& approved.revision == revision
					&& approved.remote_inner == inner
			}
			_ => false,
		};
		if !approved {
			return Err(FrontdoorError::Route);
		}
		let authority = profile.authority.clone();
		match self.source.path() {
			RemotePath::AccountRelative(path) => {
				RemoteDownloadSource::new(authority, profile.pin_digest, route, path)
			}
			RemotePath::Absolute(path) => {
				RemoteDownloadSource::new_absolute(authority, profile.pin_digest, route, path)
			}
		}
		.map_err(FrontdoorError::SignedSource)
	}

	pub(crate) fn load_profile(&self) -> Result<SshProfile, FrontdoorError> {
		let profile = SshProfile::load(&self.ssh_profile)?;
		profile.require_source(&self.source)?;
		Ok(profile)
	}
}

impl fmt::Debug for GetRequest {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("GetRequest").finish_non_exhaustive()
	}
}

pub(crate) fn require_metadata(
	value: Option<&str>,
) -> Result<ApprovedSftpMetadata, FrontdoorError> {
	let selection = match value {
		None => RemoteMetadataSelection::default(),
		Some(SftpDataOnlyV1::NAME) => RemoteMetadataSelection::SftpDataOnlyV1,
		Some(_) => return Err(FrontdoorError::MetadataSelector),
	};
	admit_sftp_metadata(selection).map_err(|_| FrontdoorError::MetadataRequired)
}
