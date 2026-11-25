use super::authority::SshAuthority;

/// Raw SHA-256 digest of an SSH public key blob.
///
/// The SSH implementation supplies the digest after cryptographic peer
/// verification. This type performs no hashing or fingerprint parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostKeyFingerprint([u8; 32]);

impl HostKeyFingerprint {
	/// Wraps the decoded digest bytes.
	#[must_use]
	pub const fn from_sha256(digest: [u8; 32]) -> Self {
		Self(digest)
	}
}

/// Trust lookup for the presented key at the exact requested authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownHostStatus {
	/// The presented key is authorized by the configured trust store.
	Trusted,
	/// No trust store entry establishes this authority's key.
	Unknown,
	/// The authority is known and the presented key is not authorized.
	Changed,
	/// The presented key is revoked.
	Revoked,
	/// A configured trust source could not be checked.
	Unavailable,
}

/// The host identity check refused access before authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostKeyRefusal {
	/// Trust lookup identified a revoked key.
	Revoked,
	/// Trust lookup identified a changed key.
	Changed,
	/// The explicitly configured fingerprint differs from the observed key.
	PinMismatch,
	/// No trusted record or explicit fingerprint matches the observed key.
	Unknown,
	/// Trust lookup could not evaluate the configured records.
	TrustUnavailable,
}

impl std::fmt::Display for HostKeyRefusal {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str(match self {
			Self::Revoked => "SSH host key is revoked",
			Self::Changed => "SSH host key changed",
			Self::PinMismatch => "SSH host key does not match the configured fingerprint",
			Self::Unknown => "SSH host key is unknown",
			Self::TrustUnavailable => "SSH host key trust records could not be checked",
		})
	}
}

impl std::error::Error for HostKeyRefusal {}

/// The host check for one SSH connection admitted its presented identity.
///
/// The adapter must keep this evidence with the connection that presented the
/// key and repeat the check for every reconnect. Host trust grants no file access.
#[derive(Debug)]
pub struct VerifiedHost<'a> {
	authority: &'a SshAuthority,
	fingerprint: HostKeyFingerprint,
}

/// Evaluates host trust before any authentication request.
///
/// The caller obtains the trust outcome for this authority and the observed
/// fingerprint. An unknown key can be admitted by an independently trusted
/// explicit pin. Report a failed trust lookup as `Unavailable`, even when a pin
/// is configured. Changed or revoked keys and unavailable trust records block.
///
/// # Errors
/// Returns the host identity refusal without requesting credentials.
pub fn verify_host(
	authority: &SshAuthority,
	observed: HostKeyFingerprint,
	known_host: KnownHostStatus,
	pin: Option<HostKeyFingerprint>,
) -> Result<VerifiedHost<'_>, HostKeyRefusal> {
	match known_host {
		KnownHostStatus::Changed => return Err(HostKeyRefusal::Changed),
		KnownHostStatus::Revoked => return Err(HostKeyRefusal::Revoked),
		KnownHostStatus::Unavailable => return Err(HostKeyRefusal::TrustUnavailable),
		KnownHostStatus::Trusted | KnownHostStatus::Unknown => {}
	}
	match pin {
		Some(expected) if expected != observed => return Err(HostKeyRefusal::PinMismatch),
		None if known_host == KnownHostStatus::Unknown => return Err(HostKeyRefusal::Unknown),
		Some(_) | None => {}
	}
	Ok(VerifiedHost {
		authority,
		fingerprint: observed,
	})
}

/// A single selected authentication mechanism, without secret material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialSource {
	/// Use a preselected key through an agent. Forwarding is a separate operation.
	AgentKey,
	/// Ask the credential broker for the explicit private key selected by the caller.
	SuppliedKey,
	/// Ask the credential broker for the password selected by the caller.
	SuppliedPassword,
	/// Request a password through an approved secure prompt.
	PasswordPrompt,
}

/// Interaction policy the credential broker must enforce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InteractionPolicy {
	/// An approved secure prompt may be used for an explicitly selected method.
	Allowed,
	/// None of the broker, the adapter, or a key agent may prompt.
	Forbidden,
}

/// The requested credential cannot be acquired for this authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialRefusal {
	/// The credential is scoped to a different SSH authority.
	AuthorityMismatch,
	/// The caller forbids a password prompt.
	InteractionForbidden,
}

impl std::fmt::Display for CredentialRefusal {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str(match self {
			Self::AuthorityMismatch => "SSH credential belongs to a different authority",
			Self::InteractionForbidden => "SSH password prompt requires interaction",
		})
	}
}

impl std::error::Error for CredentialRefusal {}

/// Permission to request one credential for a verified host and login account.
#[derive(Debug)]
pub struct CredentialRequest<'a> {
	authority: &'a SshAuthority,
	fingerprint: HostKeyFingerprint,
	source: CredentialSource,
	interaction: InteractionPolicy,
}

impl VerifiedHost<'_> {
	/// Checks that a selected credential belongs to the verified endpoint.
	///
	/// The actual secret broker and authentication mechanism are supplied by
	/// the adapter. A caller must also enforce interaction policy within any
	/// broker or key agent, including prompts outside ExaCopy's direct control.
	///
	/// # Errors
	/// Rejects a mismatched authority or a password prompt in unattended mode.
	pub fn request_credential(
		&self,
		credential_authority: &SshAuthority,
		source: CredentialSource,
		interaction: InteractionPolicy,
	) -> Result<CredentialRequest<'_>, CredentialRefusal> {
		if self.authority != credential_authority {
			return Err(CredentialRefusal::AuthorityMismatch);
		}
		if interaction == InteractionPolicy::Forbidden && source == CredentialSource::PasswordPrompt
		{
			return Err(CredentialRefusal::InteractionForbidden);
		}
		Ok(CredentialRequest {
			authority: self.authority,
			fingerprint: self.fingerprint,
			source,
			interaction,
		})
	}
}

impl CredentialRequest<'_> {
	/// The verified authority for the credential request.
	#[must_use]
	pub const fn authority(&self) -> &SshAuthority {
		self.authority
	}

	/// The host key at the credential request's verified authority.
	#[must_use]
	pub const fn fingerprint(&self) -> HostKeyFingerprint {
		self.fingerprint
	}

	/// The selected mechanism.
	#[must_use]
	pub const fn source(&self) -> CredentialSource {
		self.source
	}

	/// Whether the credential acquisition and authentication may interact.
	#[must_use]
	pub const fn interaction(&self) -> InteractionPolicy {
		self.interaction
	}
}
