use std::fmt;
use std::io;
use std::num::NonZeroU16;

use exacopy_endpoint::ssh_sftp::{HostKeyFingerprint, KnownHostStatus, SshAuthority};
use hmac::{Hmac, KeyInit, Mac};
use russh::keys::HashAlg;
use russh::keys::ssh_key::known_hosts::{Entry, HostPatterns, Marker};
use sha1::Sha1;

const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_LINES: usize = 4096;
const MAX_LINE_BYTES: usize = 8 * 1024;
const MAX_HOST_FIELD_BYTES: usize = 4096;
const MAX_HOSTS_PER_ENTRY: usize = 64;
const MAX_KEY_TYPE_BYTES: usize = 128;
const MAX_ENCODED_KEY_BYTES: usize = 4096;
const DEFAULT_PORT: NonZeroU16 = NonZeroU16::new(22).unwrap();
const HASH_LABEL_BYTES: usize = 60;

/// A refusal to establish a dedicated OpenSSH-format trust snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnownHostsError {
	/// The selected source could not be acquired or its protection validated.
	Unavailable,
	/// The source is not UTF-8.
	Encoding,
	/// The file, record count or a record field exceeded the selected bounds.
	Limit,
	/// A record is incomplete or malformed.
	Malformed {
		/// The one-based line number. Record contents are omitted.
		line: usize,
	},
	/// A record uses a marker, key, or host pattern outside the strict profile.
	Unsupported {
		/// The one-based line number. Record contents are omitted.
		line: usize,
	},
}

impl fmt::Display for KnownHostsError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Unavailable => formatter.write_str("SSH host trust source is unavailable"),
			Self::Encoding => formatter.write_str("SSH host trust source is not UTF-8"),
			Self::Limit => formatter.write_str("SSH host trust source exceeds the profile bounds"),
			Self::Malformed { line } => {
				write!(formatter, "malformed SSH host trust record at line {line}")
			}
			Self::Unsupported { line } => {
				write!(
					formatter,
					"unsupported SSH host trust record at line {line}"
				)
			}
		}
	}
}

impl std::error::Error for KnownHostsError {}

/// Parsed host trust for one exact SSH authority.
///
/// This profile accepts exact host names or IP literals, explicit bracketed
/// ports, comma-separated exact names, OpenSSH version-1 hashed labels, and
/// raw keys or explicitly revoked raw keys. Unsupported records block the
/// entire dedicated snapshot, including records for other authorities.
///
/// Hashed trust labels are lexical. Use the canonical lowercase DNS spelling
/// (preserving a final dot) or canonical IP spelling, with bare or bracketed
/// host at port 22 and bracketed host at other ports. A hashed revocation
/// denies that exact key throughout the snapshot because the opaque label
/// may use an equivalent spelling. This also denies reused keys at other
/// authorities. Literal revocations remain authority-scoped.
pub struct KnownHostTrust {
	authority: SshAuthority,
	trusted: Vec<HostKeyFingerprint>,
	revoked: Vec<HostKeyFingerprint>,
	opaque_revoked: Vec<HostKeyFingerprint>,
}

impl KnownHostTrust {
	/// Validates a bounded snapshot supplied by the local trust source owner.
	///
	/// The caller must acquire the bytes from its configured protected source
	/// and supply any acquisition or ownership failure as an error. A verified
	/// empty store is valid. This method performs no path lookup or filesystem
	/// validation. Reacquire the trust snapshot for each connection attempt.
	///
	/// # Errors
	/// Fails for unreadable, unvalidated, oversized, malformed, or unsupported input.
	pub fn from_snapshot(
		authority: &SshAuthority,
		snapshot: io::Result<&[u8]>,
	) -> Result<Self, KnownHostsError> {
		let bytes = snapshot.map_err(|_| KnownHostsError::Unavailable)?;
		if bytes.len() > MAX_FILE_BYTES {
			return Err(KnownHostsError::Limit);
		}
		let input = std::str::from_utf8(bytes).map_err(|_| KnownHostsError::Encoding)?;
		let mut trust = Self {
			authority: authority.clone(),
			trusted: Vec::new(),
			revoked: Vec::new(),
			opaque_revoked: Vec::new(),
		};
		for (index, line) in input.lines().enumerate() {
			if index >= MAX_LINES || line.len() > MAX_LINE_BYTES {
				return Err(KnownHostsError::Limit);
			}
			let number = index + 1;
			if line
				.bytes()
				.any(|byte| byte.is_ascii_control() && byte != b'\t')
			{
				return Err(KnownHostsError::Malformed { line: number });
			}
			let line = line.trim_ascii();
			if line.is_empty() || line.starts_with('#') {
				continue;
			}
			let (hosts, entry) = parse_entry(line, number)?;
			let patterns = entry.host_patterns();
			let matched = matches_authority(hosts, patterns, authority, number)?;
			let opaque_revocation = !matched
				&& entry.marker() == Some(&Marker::Revoked)
				&& matches!(patterns, HostPatterns::HashedName { .. });
			if !matched && !opaque_revocation {
				continue;
			}
			let digest = entry
				.public_key()
				.fingerprint(HashAlg::Sha256)
				.sha256()
				.ok_or(KnownHostsError::Malformed { line: number })?;
			let fingerprint = HostKeyFingerprint::from_sha256(digest);
			match entry.marker() {
				Some(Marker::Revoked) if opaque_revocation => {
					trust.opaque_revoked.push(fingerprint)
				}
				Some(Marker::Revoked) => trust.revoked.push(fingerprint),
				None => trust.trusted.push(fingerprint),
				Some(Marker::CertAuthority) => {
					return Err(KnownHostsError::Unsupported { line: number });
				}
			}
		}
		Ok(trust)
	}

	pub(crate) fn binds(&self, authority: &SshAuthority) -> bool {
		&self.authority == authority
	}

	/// Evaluates the verified SHA-256 key digest at the bound authority.
	#[must_use]
	pub fn status(
		&self,
		authority: &SshAuthority,
		fingerprint: HostKeyFingerprint,
	) -> KnownHostStatus {
		if !self.binds(authority) {
			KnownHostStatus::Unavailable
		} else if self.revoked.contains(&fingerprint) || self.opaque_revoked.contains(&fingerprint)
		{
			KnownHostStatus::Revoked
		} else if self.trusted.contains(&fingerprint) {
			KnownHostStatus::Trusted
		} else if self.trusted.is_empty() && self.revoked.is_empty() {
			KnownHostStatus::Unknown
		} else {
			KnownHostStatus::Changed
		}
	}
}

fn parse_entry(line: &str, number: usize) -> Result<(&str, Entry), KnownHostsError> {
	let malformed = KnownHostsError::Malformed { line: number };
	let unsupported = KnownHostsError::Unsupported { line: number };
	let mut fields = line.split_ascii_whitespace();
	let first = fields.next().ok_or(malformed)?;
	let (marker, hosts) = if first.starts_with('@') {
		if first.parse::<Marker>() != Ok(Marker::Revoked) {
			return Err(unsupported);
		}
		(true, fields.next().ok_or(malformed)?)
	} else {
		(false, first)
	};
	let algorithm = fields.next().ok_or(malformed)?;
	let key = fields.next().ok_or(malformed)?;
	if hosts.len() > MAX_HOST_FIELD_BYTES
		|| algorithm.len() > MAX_KEY_TYPE_BYTES
		|| key.len() > MAX_ENCODED_KEY_BYTES
	{
		return Err(KnownHostsError::Limit);
	}
	if algorithm.ends_with("-cert-v01@openssh.com")
		|| hosts.contains(['*', '?', '!'])
		|| (hosts.starts_with('|') && !hosts.starts_with("|1|"))
	{
		return Err(unsupported);
	}
	if hosts.starts_with("|1|") {
		if hosts.len() != HASH_LABEL_BYTES {
			return Err(malformed);
		}
	} else {
		let mut count = 0;
		for host in hosts.split(',') {
			if host.is_empty() {
				return Err(malformed);
			}
			count += 1;
			if count > MAX_HOSTS_PER_ENTRY {
				return Err(KnownHostsError::Limit);
			}
		}
	}
	// Normalize only whitespace between the required fields. Comments are
	// omitted before the library's typed key and host-pattern decoder.
	let normalized = if marker {
		format!("@revoked {hosts} {algorithm} {key}")
	} else {
		format!("{hosts} {algorithm} {key}")
	};
	let entry = normalized.parse().map_err(|_| malformed)?;
	Ok((hosts, entry))
}

fn matches_authority(
	host_field: &str,
	patterns: &HostPatterns,
	authority: &SshAuthority,
	number: usize,
) -> Result<bool, KnownHostsError> {
	let malformed = KnownHostsError::Malformed { line: number };
	match patterns {
		HostPatterns::Patterns(names) => {
			let mut matched = false;
			for name in names {
				let (name, port) = literal_host(name).ok_or(malformed)?;
				let stored =
					SshAuthority::new(name, port, authority.account()).map_err(|_| malformed)?;
				matched |= stored == *authority;
			}
			Ok(matched)
		}
		HostPatterns::HashedName { salt, hash } => {
			if salt.len() != 20 || patterns.to_string() != host_field {
				return Err(malformed);
			}
			let mac = Hmac::<Sha1>::new_from_slice(salt).map_err(|_| malformed)?;
			if authority.port() == DEFAULT_PORT
				&& mac
					.clone()
					.chain_update(authority.host())
					.verify_slice(hash)
					.is_ok()
			{
				return Ok(true);
			}
			let label = format!("[{}]:{}", authority.host(), authority.port());
			Ok(mac.chain_update(label).verify_slice(hash).is_ok())
		}
	}
}

fn literal_host(host: &str) -> Option<(&str, NonZeroU16)> {
	if let Some(bracketed) = host.strip_prefix('[') {
		let (name, port) = bracketed.split_once("]:")?;
		if port.len() > 5 || port.starts_with('0') || !port.bytes().all(|b| b.is_ascii_digit()) {
			return None;
		}
		Some((name, port.parse().ok()?))
	} else {
		Some((host, DEFAULT_PORT))
	}
}
