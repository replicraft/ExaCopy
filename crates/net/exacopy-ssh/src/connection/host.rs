use exacopy_endpoint::ssh_sftp::{HostKeyFingerprint, KnownHostStatus, SshAuthority, verify_host};
use russh::client::{self, ChannelOpenHandle, Handler, Msg};
use russh::keys::{HashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{Channel, Names};
use tokio::sync::oneshot;

use crate::Error;
use crate::known_hosts::KnownHostTrust;

#[cfg(test)]
mod tests;

enum HostExchange {
	AwaitingInitialIdentity,
	InitialApproved,
	Established,
	RekeyApproved,
}

pub(super) struct HostCheck {
	authority: SshAuthority,
	pin: HostKeyFingerprint,
	trust: KnownHostTrust,
	verified: Option<oneshot::Sender<(HostKeyFingerprint, KnownHostStatus)>>,
	exchange: HostExchange,
}

impl HostCheck {
	pub(super) fn new(
		authority: SshAuthority,
		pin: HostKeyFingerprint,
		trust: KnownHostTrust,
		verified: oneshot::Sender<(HostKeyFingerprint, KnownHostStatus)>,
	) -> Self {
		Self {
			authority,
			pin,
			trust,
			verified: Some(verified),
			exchange: HostExchange::AwaitingInitialIdentity,
		}
	}

	fn check_identity(
		&self,
		presented: &PublicKeyOrCertificate,
	) -> Result<(HostKeyFingerprint, KnownHostStatus), Error> {
		let PublicKeyOrCertificate::PublicKey { key, .. } = presented else {
			return Err(Error::HostCertificate);
		};
		let fingerprint = key
			.fingerprint(HashAlg::Sha256)
			.sha256()
			.ok_or(Error::Protocol)?;
		let fingerprint = HostKeyFingerprint::from_sha256(fingerprint);
		let known = self.trust.status(&self.authority, fingerprint);
		verify_host(&self.authority, fingerprint, known, Some(self.pin)).map_err(Error::HostKey)?;
		Ok((fingerprint, known))
	}
}

impl Handler for HostCheck {
	type Error = Error;

	async fn check_server_key(
		&mut self,
		presented: &PublicKeyOrCertificate,
	) -> Result<bool, Error> {
		if !matches!(self.exchange, HostExchange::AwaitingInitialIdentity) {
			return Err(Error::KeyExchange);
		}
		let proof = self.check_identity(presented)?;
		self.verified
			.take()
			.ok_or(Error::Closed)?
			.send(proof)
			.map_err(|_| Error::Closed)?;
		self.exchange = HostExchange::InitialApproved;
		Ok(true)
	}

	async fn check_server_key_on_rekey(
		&mut self,
		presented: &PublicKeyOrCertificate,
	) -> Result<bool, Error> {
		if !matches!(self.exchange, HostExchange::Established) {
			return Err(Error::KeyExchange);
		}
		self.check_identity(presented)?;
		self.exchange = HostExchange::RekeyApproved;
		Ok(true)
	}

	async fn kex_done(
		&mut self,
		_shared_secret: Option<&[u8]>,
		names: &Names,
		_session: &mut client::Session,
	) -> Result<(), Error> {
		if !names.strict_kex() {
			return Err(Error::KeyExchange);
		}
		match self.exchange {
			HostExchange::InitialApproved | HostExchange::RekeyApproved => {
				self.exchange = HostExchange::Established;
			}
			HostExchange::Established => return Err(Error::Rekey),
			HostExchange::AwaitingInitialIdentity => return Err(Error::KeyExchange),
		}
		Ok(())
	}

	// These known peer-initiated channels are accepted by russh's default
	// callbacks. This profile has no forwarding or peer-initiated services.
	async fn server_channel_open_forwarded_tcpip(
		&mut self,
		_channel: Channel<Msg>,
		_connected_address: &str,
		_connected_port: u32,
		_originator_address: &str,
		_originator_port: u32,
		_reply: ChannelOpenHandle,
		_session: &mut client::Session,
	) -> Result<(), Error> {
		Err(Error::UnsolicitedChannel)
	}

	async fn server_channel_open_forwarded_streamlocal(
		&mut self,
		_channel: Channel<Msg>,
		_socket_path: &str,
		_reply: ChannelOpenHandle,
		_session: &mut client::Session,
	) -> Result<(), Error> {
		Err(Error::UnsolicitedChannel)
	}

	async fn server_channel_open_agent_forward(
		&mut self,
		_channel: Channel<Msg>,
		_reply: ChannelOpenHandle,
		_session: &mut client::Session,
	) -> Result<(), Error> {
		Err(Error::UnsolicitedChannel)
	}

	async fn server_channel_open_session(
		&mut self,
		_channel: Channel<Msg>,
		_reply: ChannelOpenHandle,
		_session: &mut client::Session,
	) -> Result<(), Error> {
		Err(Error::UnsolicitedChannel)
	}

	async fn server_channel_open_direct_tcpip(
		&mut self,
		_channel: Channel<Msg>,
		_host_to_connect: &str,
		_port_to_connect: u32,
		_originator_address: &str,
		_originator_port: u32,
		_reply: ChannelOpenHandle,
		_session: &mut client::Session,
	) -> Result<(), Error> {
		Err(Error::UnsolicitedChannel)
	}

	async fn server_channel_open_direct_streamlocal(
		&mut self,
		_channel: Channel<Msg>,
		_socket_path: &str,
		_reply: ChannelOpenHandle,
		_session: &mut client::Session,
	) -> Result<(), Error> {
		Err(Error::UnsolicitedChannel)
	}

	async fn server_channel_open_x11(
		&mut self,
		_channel: Channel<Msg>,
		_originator_address: &str,
		_originator_port: u32,
		_reply: ChannelOpenHandle,
		_session: &mut client::Session,
	) -> Result<(), Error> {
		Err(Error::UnsolicitedChannel)
	}

	async fn openssh_ext_host_keys_announced(
		&mut self,
		_keys: Vec<PublicKey>,
		_session: &mut client::Session,
	) -> Result<(), Error> {
		Ok(())
	}
}
