use std::ffi::OsStr;
use std::net::Ipv6Addr;
use std::num::NonZeroU16;

use exacopy_endpoint::{UnixComponent, ssh_sftp::SshAuthority};
use exacopy_journal::remote_download::MAX_REMOTE_PATH_BYTES;

use super::FrontdoorError;

const MAX_AUTHORITY_BYTES: usize = 512;

pub(crate) struct RemoteOperand {
	host: Box<str>,
	account: Box<str>,
	path: Box<[u8]>,
}

pub(crate) enum RemotePath<'a> {
	AccountRelative(&'a [u8]),
	Absolute(&'a [u8]),
}

impl RemoteOperand {
	pub(super) fn parse(value: &OsStr) -> Result<Self, FrontdoorError> {
		Self::parse_bytes(super::native::remote_bytes(value)?)
	}

	fn parse_bytes(bytes: &[u8]) -> Result<Self, FrontdoorError> {
		if bytes.len() > MAX_AUTHORITY_BYTES + MAX_REMOTE_PATH_BYTES + 1 {
			return Err(FrontdoorError::Operand);
		}
		let at = bytes
			.iter()
			.position(|&byte| byte == b'@')
			.ok_or(FrontdoorError::Operand)?;
		let account = std::str::from_utf8(&bytes[..at]).map_err(|_| FrontdoorError::Operand)?;
		let (host, path) = split_host_path(&bytes[at + 1..])?;
		let host = std::str::from_utf8(host).map_err(|_| FrontdoorError::Operand)?;
		if at + 1 + host.len() > MAX_AUTHORITY_BYTES {
			return Err(FrontdoorError::Operand);
		}
		let authority = named_authority(host, NonZeroU16::MIN, account)?;
		let relative_components = path.strip_prefix(b"/").unwrap_or(path);
		if path.len() > MAX_REMOTE_PATH_BYTES
			|| relative_components
				.split(|&byte| byte == b'/')
				.any(|part| UnixComponent::new(part).is_err())
		{
			return Err(FrontdoorError::RemotePath);
		}
		Ok(Self {
			host: authority.host().into(),
			account: authority.account().into(),
			path: path.into(),
		})
	}

	pub(crate) fn authority(&self, port: NonZeroU16) -> Result<SshAuthority, FrontdoorError> {
		named_authority(&self.host, port, &self.account)
	}

	pub(crate) fn path(&self) -> RemotePath<'_> {
		if self.path.starts_with(b"/") {
			return RemotePath::Absolute(&self.path);
		}
		RemotePath::AccountRelative(&self.path)
	}
}

pub(super) fn named_authority(
	host: &str,
	port: NonZeroU16,
	account: &str,
) -> Result<SshAuthority, FrontdoorError> {
	if account
		.chars()
		.any(|ch| ch.is_whitespace() || matches!(ch, '@' | ':' | '/' | '\\' | '[' | ']'))
	{
		return Err(FrontdoorError::Operand);
	}
	SshAuthority::new(host, port, account).map_err(|_| FrontdoorError::Operand)
}

fn split_host_path(rest: &[u8]) -> Result<(&[u8], &[u8]), FrontdoorError> {
	if let Some(bracketed) = rest.strip_prefix(b"[") {
		let end = bracketed
			.iter()
			.position(|&byte| byte == b']')
			.ok_or(FrontdoorError::Operand)?;
		let (host, tail) = bracketed.split_at(end);
		if std::str::from_utf8(host)
			.ok()
			.and_then(|host| host.parse::<Ipv6Addr>().ok())
			.is_none()
		{
			return Err(FrontdoorError::Operand);
		}
		let path = tail.strip_prefix(b"]:").ok_or(FrontdoorError::Operand)?;
		return Ok((host, path));
	}
	let colon = rest
		.iter()
		.position(|&byte| byte == b':')
		.ok_or(FrontdoorError::Operand)?;
	let (host, path) = (&rest[..colon], &rest[colon + 1..]);
	// A later delimiter must not also be consistent with an unbracketed
	// IPv6 authority. Ordinary colon-bearing filename bytes survive.
	const MAX_LITERAL_BYTES: usize = 128;
	for (index, &byte) in rest.iter().enumerate().take(MAX_LITERAL_BYTES) {
		if byte == b'/' {
			break;
		}
		if byte == b':'
			&& std::str::from_utf8(&rest[..index]).is_ok_and(|prefix| {
				let address = prefix.split_once('%').map_or(prefix, |(ip, _)| ip);
				address.parse::<Ipv6Addr>().is_ok()
			}) {
			return Err(FrontdoorError::Operand);
		}
	}
	Ok((host, path))
}

#[cfg(test)]
mod tests;
