use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use exacopy_endpoint::ssh_sftp::{
	CredentialRequest, CredentialSource, HostKeyFingerprint, HostKeyRefusal, InteractionPolicy,
	SshAuthority, verify_host,
};
use russh::client::{self, AuthResult};
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg};
use russh::{Preferred, cipher, compression, kex, mac};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tokio::time::{Instant, timeout_at};
use zeroize::Zeroizing;

use crate::data::ReadOnlySftp;
use crate::error::Error;
use crate::fence::FencedStream;
use crate::known_hosts::KnownHostTrust;
use crate::wire::Wire;

mod host;
mod keepalive;
mod protected_key;
mod subsystem;

use host::HostCheck;

pub use protected_key::MAX_OPENSSH_ED25519_BYTES;

const MAX_PASSWORD_BYTES: usize = 4096;
const CONNECT_DEADLINE: Duration = Duration::from_secs(20);

/// The host and login identity verified for one authenticated SFTP session.
///
/// This value records the initial authenticated peer. Session I/O reports
/// subsequent connection closure.
pub struct SshAuthenticatedPeer {
	authority: SshAuthority,
	fingerprint: HostKeyFingerprint,
}

impl SshAuthenticatedPeer {
	/// The authority and account used by the verified authentication.
	#[must_use]
	pub const fn authority(&self) -> &SshAuthority {
		&self.authority
	}

	/// The fingerprint observed from the verified SSH host key.
	#[must_use]
	pub const fn fingerprint(&self) -> HostKeyFingerprint {
		self.fingerprint
	}
}

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

/// A caller-supplied Ed25519 private key for one authentication attempt.
///
/// This wrapper exposes no key bytes or formatting. The seed and upstream
/// private key storage are wiped on drop, subject to their respective library
/// guarantees. It makes no guarantee about other copies or process memory.
pub struct Ed25519Key(PrivateKey);

impl Ed25519Key {
	/// Constructs a key using the upstream SSH key library and takes ownership of the seed.
	///
	/// # Errors
	/// Returns a credential error if the library cannot construct the key.
	pub fn from_seed(seed: Zeroizing<[u8; 32]>) -> Result<Self, Error> {
		let keypair = Ed25519Keypair::from_seed(&seed);
		PrivateKey::new(KeypairData::Ed25519(keypair), "")
			.map(Self)
			.map_err(Error::Key)
	}
}

trait Authentication {
	const SOURCE: CredentialSource;
	const REFUSAL: Error;

	async fn authenticate(
		self,
		connection: &mut client::Handle<HostCheck>,
		account: &str,
	) -> Result<AuthResult, russh::Error>;
}

impl Authentication for Password {
	const SOURCE: CredentialSource = CredentialSource::SuppliedPassword;
	const REFUSAL: Error = Error::Authentication;

	async fn authenticate(
		mut self,
		connection: &mut client::Handle<HostCheck>,
		account: &str,
	) -> Result<AuthResult, russh::Error> {
		let secret = std::mem::take(&mut *self.0);
		connection.authenticate_password(account, secret).await
	}
}

impl Authentication for Ed25519Key {
	const SOURCE: CredentialSource = CredentialSource::SuppliedKey;
	const REFUSAL: Error = Error::KeyAuthentication;

	async fn authenticate(
		self,
		connection: &mut client::Handle<HostCheck>,
		account: &str,
	) -> Result<AuthResult, russh::Error> {
		let key = PrivateKeyWithHashAlg::new(Arc::new(self.0), None);
		connection.authenticate_publickey(account, key).await
	}
}

/// Connects to a pinned SFTP peer over a stream supplied by the route owner.
///
/// Supply the parsed trust snapshot for this authority. The caller owns
/// route enforcement and provides a bounded, nonblocking credential broker.
/// The adapter calls the broker at most once, after accepting host trust on
/// the same connection.
///
/// # Errors
/// A failure to establish SSH/SFTP or acquire an approved credential is returned.
/// The adapter makes no connection retries and never opens a shell.
pub async fn connect<S, B>(
	stream: S,
	authority: &SshAuthority,
	pin: HostKeyFingerprint,
	trust: KnownHostTrust,
	credential_authority: &SshAuthority,
	broker: B,
) -> Result<ReadOnlySftp, Error>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	B: FnOnce(CredentialRequest<'_>) -> Result<Password, Error>,
{
	connect_with_credential(
		stream,
		authority,
		pin,
		trust,
		credential_authority,
		async move |request| broker(request),
		|| Ok(()),
	)
	.await
}

/// Connects to a pinned SFTP peer with one caller-supplied Ed25519 key.
///
/// The broker is called after the SSH peer and credential authority have
/// been verified. It must be bounded and nonblocking. The key is used only
/// for authentication on the verified connection. The adapter exposes no
/// ambient key discovery, agent forwarding, or shell operation.
///
/// # Errors
/// A failure to establish SSH/SFTP or obtain an approved key is returned.
/// A rejected key ends the attempt.
pub async fn connect_with_ed25519<S, B>(
	stream: S,
	authority: &SshAuthority,
	pin: HostKeyFingerprint,
	trust: KnownHostTrust,
	credential_authority: &SshAuthority,
	broker: B,
) -> Result<ReadOnlySftp, Error>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	B: FnOnce(CredentialRequest<'_>) -> Result<Ed25519Key, Error>,
{
	connect_with_credential(
		stream,
		authority,
		pin,
		trust,
		credential_authority,
		async move |request| broker(request),
		|| Ok(()),
	)
	.await
}

/// Connect to a pinned SFTP peer with a broker that can await protected key acquisition.
///
/// The future starts after host verification. A broker that performs native
/// I/O or decrypts a key should use a bounded blocking worker. The offer
/// check runs after that future resolves, immediately before authentication.
///
/// # Errors
/// Returns a refusal if the broker, live offer check, peer or SFTP setup fails.
pub async fn connect_with_ed25519_async<S, B>(
	stream: S,
	authority: &SshAuthority,
	pin: HostKeyFingerprint,
	trust: KnownHostTrust,
	credential_authority: &SshAuthority,
	broker: B,
	offer_current: impl FnOnce() -> Result<(), Error>,
) -> Result<ReadOnlySftp, Error>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	B: for<'a> AsyncFnOnce(CredentialRequest<'a>) -> Result<Ed25519Key, Error>,
{
	connect_with_credential(
		stream,
		authority,
		pin,
		trust,
		credential_authority,
		broker,
		offer_current,
	)
	.await
}

async fn connect_with_credential<S, B, C>(
	stream: S,
	authority: &SshAuthority,
	pin: HostKeyFingerprint,
	trust: KnownHostTrust,
	credential_authority: &SshAuthority,
	broker: B,
	offer_current: impl FnOnce() -> Result<(), Error>,
) -> Result<ReadOnlySftp, Error>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	B: for<'a> AsyncFnOnce(CredentialRequest<'a>) -> Result<C, Error>,
	C: Authentication,
{
	if !trust.binds(authority) {
		return Err(Error::HostKey(HostKeyRefusal::TrustUnavailable));
	}
	let deadline = Instant::now() + CONNECT_DEADLINE;
	timeout_at(deadline, async {
		let (verified, checked) = oneshot::channel();
		let handler = HostCheck::new(authority.clone(), pin, trust, verified);
		let (stream, guard, cancellation) = FencedStream::new(stream);
		let mut connection = client::connect_stream(Arc::new(config()), stream, handler).await?;
		let (fingerprint, known) = checked.await.map_err(|_| Error::Closed)?;
		let verified =
			verify_host(authority, fingerprint, known, Some(pin)).map_err(Error::HostKey)?;
		let request = verified
			.request_credential(
				credential_authority,
				C::SOURCE,
				InteractionPolicy::Forbidden,
			)
			.map_err(Error::Credential)?;
		let authority = request.authority().clone();
		let fingerprint = request.fingerprint();
		let credential = broker(request).await?;
		if Instant::now() >= deadline {
			return Err(Error::Timeout);
		}
		offer_current()?;
		if !credential
			.authenticate(&mut connection, authority.account())
			.await?
			.success()
		{
			return Err(C::REFUSAL);
		}

		let mut channel = connection.channel_open_session().await?;
		channel.request_subsystem(true, "sftp").await?;
		subsystem::confirm(async || channel.wait().await).await?;
		let wire = Wire::init(channel.into_stream()).await?;
		let peer = SshAuthenticatedPeer {
			authority,
			fingerprint,
		};
		let (connection, guard) = keepalive::supervise(connection, guard);
		Ok(ReadOnlySftp::new(
			wire,
			Box::pin(connection),
			guard,
			peer,
			cancellation,
		))
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
