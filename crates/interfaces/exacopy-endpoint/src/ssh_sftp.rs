//! Admission policy for the initial SSH/SFTP source profile.
//!
//! An SSH adapter supplies host-key and SFTP handshake observations. These
//! decisions neither open connections nor authorize access to a remote root.

mod authority;
mod capabilities;
mod trust;

pub use authority::{AuthorityError, SshAuthority};
pub use capabilities::{SftpAdvertisement, SftpCapabilities, SftpRefusal, SftpVersionError};
pub use trust::{
	CredentialRefusal, CredentialRequest, CredentialSource, HostKeyFingerprint, HostKeyRefusal,
	InteractionPolicy, KnownHostStatus, VerifiedHost, verify_host,
};
