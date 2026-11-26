use std::ffi::OsString;
use std::path::{Path, PathBuf};

use exacopy_platform::{ProtectedSnapshotError, read_protected_snapshot_into};
use exacopy_ssh::{Ed25519Key, Error as SshError, MAX_OPENSSH_ED25519_BYTES};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::super::native::key_passphrase;
use super::{FrontdoorError, PublicDigest, protected_path};

#[cfg(all(test, unix))]
mod tests;

const MAX_ENV_NAME_BYTES: usize = 128;
const MAX_PASSPHRASE_BYTES: usize = 4096;
const READBACK_BYTES: usize = 4096;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum WireCredential {
	PasswordEnv {
		name: String,
	},
	OpensshEd25519 {
		private_key_file: PathBuf,
		public_key_sha256: PublicDigest,
		passphrase_env: Option<String>,
	},
}

#[derive(Eq, PartialEq)]
pub(super) enum Credential {
	PasswordEnv(EnvReference),
	OpenSshEd25519(ProtectedEd25519),
}

impl WireCredential {
	pub(super) fn admit(self) -> Result<Credential, FrontdoorError> {
		Ok(match self {
			Self::PasswordEnv { name } => Credential::PasswordEnv(EnvReference::new(name)?),
			Self::OpensshEd25519 {
				private_key_file,
				public_key_sha256,
				passphrase_env,
			} => Credential::OpenSshEd25519(ProtectedEd25519 {
				private_key_file: protected_path(private_key_file)?,
				public_key_sha256,
				passphrase_env: passphrase_env.map(EnvReference::new).transpose()?,
			}),
		})
	}
}

/// One selected key reference approved for the actual verified SSH peer.
/// Move it into a blocking worker only for that connection's live grant.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ProtectedEd25519 {
	private_key_file: PathBuf,
	public_key_sha256: PublicDigest,
	passphrase_env: Option<EnvReference>,
}

impl ProtectedEd25519 {
	/// Reacquire and decode the selected protected key under the current grant.
	/// Call from a bounded blocking worker. The SSH offer gate checks the same
	/// grant again on the connection task before starting authentication.
	pub(crate) fn acquire(
		self,
		grant_current: impl FnMut() -> bool,
	) -> Result<Ed25519Key, SshError> {
		self.acquire_from(grant_current, read_protected_snapshot_into, |name| {
			std::env::var_os(name)
		})
	}

	fn acquire_from(
		self,
		mut grant_current: impl FnMut() -> bool,
		read: impl FnOnce(&Path, &mut [u8], &mut [u8]) -> Result<usize, ProtectedSnapshotError>,
		lookup: impl FnOnce(&str) -> Option<OsString>,
	) -> Result<Ed25519Key, SshError> {
		if !grant_current() {
			return Err(SshError::KeyProfile);
		}
		let mut bytes = Zeroizing::new(vec![0; MAX_OPENSSH_ED25519_BYTES]);
		let mut readback = Zeroizing::new([0; READBACK_BYTES]);
		let length = read(&self.private_key_file, &mut bytes, &mut *readback)
			.map_err(|_| SshError::KeyProfile)?;
		let encoded = bytes.get(..length).ok_or(SshError::KeyProfile)?;
		if !grant_current() {
			return Err(SshError::KeyProfile);
		}

		let passphrase = self
			.passphrase_env
			.map(|reference| read_passphrase(&reference, lookup))
			.transpose()?;
		let key = Ed25519Key::from_openssh(
			encoded,
			passphrase.as_deref().map(Vec::as_slice),
			self.public_key_sha256.0,
		)?;
		if !grant_current() {
			return Err(SshError::KeyProfile);
		}
		Ok(key)
	}
}

fn read_passphrase(
	reference: &EnvReference,
	lookup: impl FnOnce(&str) -> Option<OsString>,
) -> Result<Zeroizing<Vec<u8>>, SshError> {
	let value = lookup(reference.name()).ok_or(SshError::KeyProfile)?;
	key_passphrase(value, MAX_PASSPHRASE_BYTES).ok_or(SshError::KeyProfile)
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct EnvReference(String);

impl EnvReference {
	fn new(name: String) -> Result<Self, FrontdoorError> {
		let mut bytes = name.bytes();
		let valid = name.len() <= MAX_ENV_NAME_BYTES
			&& bytes
				.next()
				.is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
			&& bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
		if !valid {
			return Err(FrontdoorError::CredentialReference);
		}
		Ok(Self(name))
	}

	pub(super) fn name(&self) -> &str {
		&self.0
	}
}
