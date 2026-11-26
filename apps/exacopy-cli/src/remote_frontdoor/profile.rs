use std::ffi::OsString;
use std::fmt;
use std::num::{NonZeroU16, NonZeroU64};
use std::path::{Path, PathBuf};
use std::time::Duration;

use exacopy_endpoint::ssh_sftp::{
	CredentialRequest, CredentialSource, HostKeyFingerprint, InteractionPolicy, SshAuthority,
};
use exacopy_platform::read_protected_snapshot;
use exacopy_ssh::{Error as SshError, KnownHostTrust, MAX_STREAM_BYTES, Password};
use serde::{Deserialize, Deserializer};

use super::FrontdoorError;
use super::native::password_text;
pub(super) use super::native::protected_path;
use super::operand::{RemoteOperand, named_authority};
use super::route::{ApprovedRoute, WireRoute};

mod credential;

pub(crate) use credential::ProtectedEd25519;
use credential::{Credential, WireCredential};

const MAX_PROFILE_BYTES: usize = 16 * 1024;
const MAX_GRANT_SECONDS: u64 = 3600;

/// One parsed protected profile. It contains a broker reference, never key bytes or passwords.
#[derive(Eq, PartialEq)]
pub(crate) struct SshProfile {
	pub(crate) authority: SshAuthority,
	pub(crate) pin: HostKeyFingerprint,
	pub(crate) pin_digest: [u8; 32],
	pub(crate) route: ApprovedRoute,
	pub(crate) maximum_extent: u64,
	pub(crate) grant_duration: Duration,
	known_hosts: PathBuf,
	credential: Credential,
}

impl fmt::Debug for SshProfile {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("SshProfile").finish_non_exhaustive()
	}
}

impl SshProfile {
	pub(crate) fn load(path: &Path) -> Result<Self, FrontdoorError> {
		let bytes = read_protected_snapshot(path).map_err(FrontdoorError::Protected)?;
		Self::decode(&bytes)
	}

	pub(crate) fn require_source(&self, source: &RemoteOperand) -> Result<(), FrontdoorError> {
		if source.authority(self.authority.port())? != self.authority {
			return Err(FrontdoorError::Authority);
		}
		Ok(())
	}

	/// Reacquire the explicitly selected trust snapshot for every connection.
	pub(crate) fn read_trust(&self) -> Result<KnownHostTrust, FrontdoorError> {
		let bytes =
			read_protected_snapshot(&self.known_hosts).map_err(FrontdoorError::Protected)?;
		KnownHostTrust::from_snapshot(&self.authority, Ok(&bytes)).map_err(FrontdoorError::Trust)
	}

	/// Select one broker method without acquiring its credential.
	pub(crate) fn credential_source(&self) -> CredentialSource {
		match self.credential {
			Credential::PasswordEnv(_) => CredentialSource::SuppliedPassword,
			Credential::OpenSshEd25519(_) => CredentialSource::SuppliedKey,
		}
	}

	/// Approve the selected key reference for this verified SSH request.
	/// Reading the key requires a live grant checked by the bounded worker.
	pub(crate) fn approve_ed25519(
		&self,
		request: CredentialRequest<'_>,
	) -> Result<ProtectedEd25519, SshError> {
		let Credential::OpenSshEd25519(reference) = &self.credential else {
			return Err(SshError::KeyProfile);
		};
		if !self.matches_request(&request, CredentialSource::SuppliedKey) {
			return Err(SshError::KeyProfile);
		}
		Ok(reference.clone())
	}

	fn matches_request(&self, request: &CredentialRequest<'_>, source: CredentialSource) -> bool {
		request.authority() == &self.authority
			&& request.fingerprint() == self.pin
			&& request.source() == source
			&& request.interaction() == InteractionPolicy::Forbidden
	}

	/// Provide this callback only inside the supervisor's still-live grant.
	/// The SSH adapter calls it once after actual verified host admission.
	pub(crate) fn password(
		&self,
		request: CredentialRequest<'_>,
		grant_current: impl FnOnce() -> bool,
	) -> Result<Password, SshError> {
		self.password_from(request, grant_current, |name| std::env::var_os(name))
	}

	pub(super) fn password_from(
		&self,
		request: CredentialRequest<'_>,
		grant_current: impl FnOnce() -> bool,
		lookup: impl FnOnce(&str) -> Option<OsString>,
	) -> Result<Password, SshError> {
		let Credential::PasswordEnv(reference) = &self.credential else {
			return Err(SshError::Password);
		};
		if !self.matches_request(&request, CredentialSource::SuppliedPassword) || !grant_current() {
			return Err(SshError::Password);
		}
		let raw = lookup(reference.name()).ok_or(SshError::Password)?;
		let secret = password_text(raw).ok_or(SshError::Password)?;
		Password::new(secret)
	}

	pub(super) fn decode(bytes: &[u8]) -> Result<Self, FrontdoorError> {
		if bytes.len() > MAX_PROFILE_BYTES {
			return Err(FrontdoorError::ProfileSize);
		}
		let wire: WireProfile =
			serde_json::from_slice(bytes).map_err(|_| FrontdoorError::ProfileSyntax)?;
		let Schema::V1 = wire.schema;
		let authority = named_authority(&wire.host, wire.port, &wire.account)?;
		let known_hosts = protected_path(wire.known_hosts)?;
		let credential = wire.credential.admit()?;
		let route = wire.route.admit(&authority)?;
		if wire.maximum_extent.get() > MAX_STREAM_BYTES
			|| wire.grant_seconds.get() > MAX_GRANT_SECONDS
		{
			return Err(FrontdoorError::ProfileBounds);
		}
		Ok(Self {
			authority,
			pin: HostKeyFingerprint::from_sha256(wire.host_key_sha256.0),
			pin_digest: wire.host_key_sha256.0,
			route,
			maximum_extent: wire.maximum_extent.get(),
			grant_duration: Duration::from_secs(wire.grant_seconds.get()),
			known_hosts,
			credential,
		})
	}
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProfile {
	schema: Schema,
	host: String,
	port: NonZeroU16,
	account: String,
	host_key_sha256: PublicDigest,
	known_hosts: PathBuf,
	credential: WireCredential,
	route: WireRoute,
	maximum_extent: NonZeroU64,
	grant_seconds: NonZeroU64,
}

#[derive(Deserialize)]
enum Schema {
	#[serde(rename = "exacopy-ssh-profile-v1")]
	V1,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct PublicDigest(pub(super) [u8; 32]);

impl<'de> Deserialize<'de> for PublicDigest {
	fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		let value = String::deserialize(deserializer)?;
		parse_digest(value.as_bytes())
			.ok_or_else(|| serde::de::Error::custom("invalid public digest"))
	}
}

fn parse_digest(value: &[u8]) -> Option<PublicDigest> {
	let mut digest = [0; 32];
	let (pairs, remainder) = value.as_chunks::<2>();
	if pairs.len() != digest.len() || !remainder.is_empty() {
		return None;
	}
	for (&[high, low], output) in pairs.iter().zip(&mut digest) {
		*output = (hex_digit(high)? << 4) | hex_digit(low)?;
	}
	(digest != [0; 32]).then_some(PublicDigest(digest))
}

fn hex_digit(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte - b'0'),
		b'a'..=b'f' => Some(10 + byte - b'a'),
		_ => None,
	}
}
