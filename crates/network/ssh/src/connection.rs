use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use exacopy_endpoint::ssh_sftp::{
	CredentialRequest, CredentialSource, HostKeyFingerprint, InteractionPolicy, KnownHostStatus,
	SshAuthority, verify_host,
};
use russh::client::{self, ChannelOpenHandle, Handler, Msg};
use russh::keys::{Algorithm, HashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg, Names, Preferred, cipher, compression, kex, mac};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::data::ReadOnlySftp;
use crate::error::Error;
use crate::fence::FencedStream;
use crate::wire::Wire;

const MAX_PASSWORD_BYTES: usize = 4096;
const CONNECT_DEADLINE: Duration = Duration::from_secs(20);

/// A live password accepted by the prototype's supplied-password profile.
///
/// The owned buffer is wiped on drop or transferred once to russh's password
/// method, which wipes its owned copy on drop.
pub struct Password(Zeroizing<String>);

impl Password {
	/// Takes ownership of a bounded password from the trusted broker.
	///
	/// # Errors
	/// Returns a credential error for empty, oversized, or NUL-bearing input.
	pub fn new(secret: String) -> Result<Self, Error> {
		let secret = Zeroizing::new(secret);
		if secret.is_empty() || secret.len() > MAX_PASSWORD_BYTES || secret.contains('\0') {
			return Err(Error::Password);
		}
		Ok(Self(secret))
	}
}

pub(crate) struct HostCheck<T> {
	authority: SshAuthority,
	pin: HostKeyFingerprint,
	lookup: Option<T>,
	verified: Option<oneshot::Sender<(HostKeyFingerprint, KnownHostStatus)>>,
	initial_complete: bool,
}

impl<T> Handler for HostCheck<T>
where
	T: FnOnce(&SshAuthority, HostKeyFingerprint) -> KnownHostStatus + Send,
{
	type Error = Error;

	async fn check_server_key(
		&mut self,
		presented: &PublicKeyOrCertificate,
	) -> Result<bool, Error> {
		let PublicKeyOrCertificate::PublicKey { key, .. } = presented else {
			return Err(Error::HostCertificate);
		};
		let fingerprint = key
			.fingerprint(HashAlg::Sha256)
			.sha256()
			.ok_or(Error::Protocol)?;
		let fingerprint = HostKeyFingerprint::from_sha256(fingerprint);
		let lookup = self.lookup.take().ok_or(Error::Protocol)?;
		let known = lookup(&self.authority, fingerprint);
		verify_host(&self.authority, fingerprint, known, Some(self.pin)).map_err(Error::HostKey)?;
		self.verified
			.take()
			.ok_or(Error::Closed)?
			.send((fingerprint, known))
			.map_err(|_| Error::Closed)?;
		Ok(true)
	}

	async fn kex_done(
		&mut self,
		_shared_secret: Option<&[u8]>,
		names: &Names,
		_session: &mut client::Session,
	) -> Result<(), Error> {
		if self.initial_complete {
			return Err(Error::Rekey);
		}
		if !names.strict_kex() {
			return Err(Error::KeyExchange);
		}
		self.initial_complete = true;
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

/// Connects to a pinned SFTP peer over a stream supplied by the route owner.
///
/// The trust lookup uses previously acquired authority-scoped observations and
/// must be bounded and nonblocking, as must the supplied credential broker.
/// The caller owns route enforcement and credential acquisition. The adapter calls the broker at most once, on the
/// same connection, after the library and local policy accept the peer.
///
/// # Errors
/// A failure to establish SSH/SFTP or acquire an approved credential is returned.
/// The adapter makes no connection retries and never opens a shell.
pub async fn connect<S, T, B>(
	stream: S,
	authority: &SshAuthority,
	pin: HostKeyFingerprint,
	trust: T,
	credential_authority: &SshAuthority,
	broker: B,
) -> Result<ReadOnlySftp, Error>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	T: FnOnce(&SshAuthority, HostKeyFingerprint) -> KnownHostStatus + Send + 'static,
	B: FnOnce(CredentialRequest<'_>) -> Result<Password, Error>,
{
	timeout(CONNECT_DEADLINE, async {
		let (verified, checked) = oneshot::channel();
		let handler = HostCheck {
			authority: authority.clone(),
			pin,
			lookup: Some(trust),
			verified: Some(verified),
			initial_complete: false,
		};
		let (stream, guard) = FencedStream::new(stream);
		let mut connection = client::connect_stream(Arc::new(config()), stream, handler).await?;
		let (fingerprint, known) = checked.await.map_err(|_| Error::Closed)?;
		let verified =
			verify_host(authority, fingerprint, known, Some(pin)).map_err(Error::HostKey)?;
		let request = verified
			.request_credential(
				credential_authority,
				CredentialSource::SuppliedPassword,
				InteractionPolicy::Forbidden,
			)
			.map_err(Error::Credential)?;
		let mut password = broker(request)?;
		let secret = std::mem::take(&mut *password.0);
		if !connection
			.authenticate_password(authority.account(), secret)
			.await?
			.success()
		{
			return Err(Error::Authentication);
		}

		let mut channel = connection.channel_open_session().await?;
		channel.request_subsystem(true, "sftp").await?;
		if !matches!(channel.wait().await, Some(ChannelMsg::Success)) {
			return Err(Error::Subsystem);
		}
		let wire = Wire::init(channel.into_stream()).await?;
		Ok(ReadOnlySftp::new(wire, Box::pin(connection), guard))
	})
	.await
	.map_err(|_| Error::Timeout)?
}

fn config() -> client::Config {
	client::Config {
		preferred: Preferred {
			kex: Cow::Borrowed(&[kex::CURVE25519, kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT]),
			key: Cow::Borrowed(&[Algorithm::Ed25519]),
			host_key_certificates: Cow::Borrowed(&[]),
			cipher: Cow::Borrowed(&[cipher::AES_256_GCM]),
			mac: Cow::Borrowed(&[mac::HMAC_SHA256_ETM]),
			compression: Cow::Borrowed(&[compression::NONE]),
		},
		window_size: 256 * 1024,
		maximum_packet_size: 32 * 1024,
		channel_buffer_size: 8,
		inactivity_timeout: Some(CONNECT_DEADLINE),
		..client::Config::default()
	}
}
