use std::io;
use std::net::{IpAddr, SocketAddr};

use exacopy_endpoint::connection_retry::ConnectionBinding;
use exacopy_endpoint::ssh_sftp::SshAuthority;
use exacopy_endpoint::wireguard::{InnerDial, InnerDialKind};
use exacopy_endpoint::{MAX_FILE_LENGTH, UnixComponent};
use exacopy_journal::windows_bootstrap::WindowsBootstrapFileIdentity;
use exacopy_platform::windows::WindowsStageIdentity;

use super::WindowsCaptureAuthorization;

const SOURCE_DOMAIN: &[u8] = b"ExaCopy/windows-ntfs-capture/source/resolved-direct-relative/v1\0";
const GRANT_DOMAIN: &[u8] = b"ExaCopy/windows-ntfs-capture/grant/v1\0";
const MAX_RELATIVE_PATH_BYTES: u16 = 4096;

/// Independent resolved-direct SSH and account-relative SFTP selection.
pub struct WindowsCaptureSource<'a> {
	/// Canonical resolved SSH authority and case-sensitive account.
	pub authority: &'a SshAuthority,
	/// One independently allowed literal route.
	pub peer: SocketAddr,
	/// Exact expected SHA-256 host-key fingerprint.
	pub host_fingerprint: [u8; 32],
	/// Exact account-relative path selected by the caller.
	pub path: &'a [UnixComponent<'a>],
	/// Largest admitted observed source extent.
	pub extent_ceiling: u64,
}

impl WindowsCaptureSource<'_> {
	/// Computes the canonical scope digest before acquiring a route or credential.
	///
	/// # Errors
	/// Refuses an ambiguous or unsupported peer, fingerprint, path or extent.
	pub fn scope_digest(&self) -> io::Result<[u8; 32]> {
		let ip = self.peer.ip();
		if self.extent_ceiling > MAX_FILE_LENGTH
			|| self.host_fingerprint == [0; 32]
			|| self.peer.port() != self.authority.port().get()
			|| InnerDial::new(InnerDialKind::Stream, self.peer).is_none()
			|| matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local())
			|| self
				.authority
				.host()
				.parse::<IpAddr>()
				.is_ok_and(|host| host != ip)
		{
			return Err(invalid_selection());
		}
		let mut path_length: u16 = 0;
		for component in self.path {
			let length =
				u16::try_from(component.as_bytes().len()).map_err(|_| invalid_selection())?;
			path_length = path_length
				.checked_add(length)
				.and_then(|sum| sum.checked_add(u16::from(path_length != 0)))
				.filter(|sum| *sum <= MAX_RELATIVE_PATH_BYTES)
				.ok_or_else(invalid_selection)?;
		}
		if path_length == 0 {
			return Err(invalid_selection());
		}
		let mut hash = blake3::Hasher::new();
		hash.update(SOURCE_DOMAIN);
		counted_bytes(&mut hash, self.authority.host().as_bytes())?;
		hash.update(&self.authority.port().get().to_le_bytes());
		counted_bytes(&mut hash, self.authority.account().as_bytes())?;
		hash.update(&self.host_fingerprint);
		match ip {
			IpAddr::V4(value) => {
				hash.update(&[4]);
				hash.update(&value.octets());
			}
			IpAddr::V6(value) => {
				hash.update(&[16]);
				hash.update(&value.octets());
			}
		}
		hash.update(&self.peer.port().to_le_bytes());
		hash.update(&path_length.to_le_bytes());
		for (index, component) in self.path.iter().enumerate() {
			if index != 0 {
				hash.update(b"/");
			}
			hash.update(component.as_bytes());
		}
		hash.update(&self.extent_ceiling.to_le_bytes());
		Ok(*hash.finalize().as_bytes())
	}
}

pub(super) fn invocation(
	approval: &WindowsCaptureAuthorization<'_>,
	binding: ConnectionBinding,
) -> io::Result<[u8; 32]> {
	let mut hash = blake3::Hasher::new();
	hash.update(GRANT_DOMAIN);
	hash.update(&approval.nonce);
	hash.update(&approval.source_scope);
	hash.update(approval.owner_digest.as_bytes());
	hash.update(&approval.bootstrap_head.digest());
	hash.update(approval.sibling.file_id());
	hash.update(&binding.attempt().owner().id().get().to_le_bytes());
	hash.update(&binding.attempt().generation().get().to_le_bytes());
	hash.update(&binding.source_epoch().get().to_le_bytes());
	hash.update(&approval.extent_ceiling.to_le_bytes());
	let target = approval.target.as_units();
	let count = u16::try_from(target.len()).map_err(|_| invalid_selection())?;
	hash.update(&count.to_le_bytes());
	for unit in target {
		hash.update(&unit.to_le_bytes());
	}
	let digest = *hash.finalize().as_bytes();
	if digest == [0; 32] {
		return Err(invalid_selection());
	}
	Ok(digest)
}

fn counted_bytes(hash: &mut blake3::Hasher, bytes: &[u8]) -> io::Result<()> {
	let count = u16::try_from(bytes.len()).map_err(|_| invalid_selection())?;
	hash.update(&count.to_le_bytes());
	hash.update(bytes);
	Ok(())
}

pub(super) fn native_identity(
	held: WindowsStageIdentity,
) -> io::Result<WindowsBootstrapFileIdentity> {
	WindowsBootstrapFileIdentity::new(held.volume_guid(), held.volume_serial(), held.file_id())
		.map_err(|_| invalid_selection())
}

pub(super) fn invalid_selection() -> io::Error {
	io::Error::new(
		io::ErrorKind::InvalidInput,
		"invalid selected Windows capture scope",
	)
}

#[cfg(test)]
mod tests;
