use std::net::IpAddr;
use std::num::NonZeroU16;

// DNS names in presentation form, with the optional final dot removed.
const MAX_HOST_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 63;
// Local input bound for this profile. SSH itself does not impose this limit.
const MAX_ACCOUNT_BYTES: usize = 256;

/// Inputs to a resolved SSH authority must be bounded and unambiguous.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityError {
	/// The host is neither an IP literal nor a supported DNS name.
	Host,
	/// The account is empty, too long, or contains a control character.
	Account,
}

impl std::fmt::Display for AuthorityError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str(match self {
			Self::Host => "invalid SSH host",
			Self::Account => "invalid SSH account",
		})
	}
}

impl std::error::Error for AuthorityError {}

/// A resolved SSH host, numeric port, and case-sensitive login account.
///
/// Built after config precedence and alias resolution. The type accepts structured
/// fields only and never contains a password, URI, endpoint path, or resource grant.
#[derive(Clone, Eq, PartialEq)]
pub struct SshAuthority {
	host: String,
	port: NonZeroU16,
	account: String,
}

impl SshAuthority {
	/// Builds an authority from an unbracketed IP literal or ASCII DNS name.
	///
	/// Absolute DNS names retain their final dot: they can resolve differently from
	/// the corresponding name without the dot. IP address spellings normalize.
	///
	/// # Errors
	/// Rejects malformed hosts and empty, oversized, or control-bearing accounts.
	pub fn new(host: &str, port: NonZeroU16, account: &str) -> Result<Self, AuthorityError> {
		let host = canonical_host(host)?;
		if account.is_empty()
			|| account.len() > MAX_ACCOUNT_BYTES
			|| account.chars().any(char::is_control)
		{
			return Err(AuthorityError::Account);
		}
		Ok(Self {
			host,
			port,
			account: account.to_owned(),
		})
	}

	/// Returns the host to use for this authority.
	#[must_use]
	pub fn host(&self) -> &str {
		&self.host
	}

	/// Returns the port to use for this authority.
	#[must_use]
	pub fn port(&self) -> NonZeroU16 {
		self.port
	}

	/// Returns the login account to use for this authority.
	#[must_use]
	pub fn account(&self) -> &str {
		&self.account
	}
}

impl std::fmt::Debug for SshAuthority {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str("SshAuthority(<redacted>)")
	}
}

fn canonical_host(host: &str) -> Result<String, AuthorityError> {
	if host.len() > MAX_HOST_BYTES + 1 {
		return Err(AuthorityError::Host);
	}
	if let Ok(address) = host.parse::<IpAddr>() {
		return Ok(address.to_string());
	}
	let labels = host.strip_suffix('.').unwrap_or(host);
	if labels.len() > MAX_HOST_BYTES || !labels.split('.').all(valid_label) {
		return Err(AuthorityError::Host);
	}
	Ok(host.to_ascii_lowercase())
}

fn valid_label(label: &str) -> bool {
	!label.is_empty()
		&& label.len() <= MAX_LABEL_BYTES
		&& !label.starts_with('-')
		&& !label.ends_with('-')
		&& label
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}
