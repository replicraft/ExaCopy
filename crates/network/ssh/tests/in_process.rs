//! SSH/SFTP integration over bounded in-memory streams and synthetic credentials.

#![cfg(feature = "experimental-ssh")]
use std::num::NonZeroU16;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use exacopy_endpoint::UnixComponent;
use exacopy_endpoint::ssh_sftp::{
	CredentialRefusal, CredentialSource, HostKeyFingerprint, HostKeyRefusal, InteractionPolicy,
	KnownHostStatus, SshAuthority,
};
use exacopy_ssh::{Error, Password, connect};
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::{HashAlg, PrivateKey};
use russh::{Channel, ChannelId, server};
use russh_sftp::{protocol as sftp, server as sftp_server};
use tokio::io::DuplexStream;
use tokio::sync::oneshot;

const NAME: &[u8] = b"\xfffile";
const CONTENT: &[u8] = b"abcde";
const SECRET: &str = "synthetic-fixture-only";

#[derive(Default)]
struct Calls {
	auth: AtomicUsize,
	subsystem: AtomicUsize,
	unsupported: AtomicUsize,
	close: AtomicUsize,
}

struct Peer {
	channel: Option<Channel<server::Msg>>,
	calls: Arc<Calls>,
	subsystem: bool,
	early_eof: bool,
}

impl server::Handler for Peer {
	type Error = russh::Error;

	async fn auth_password(
		&mut self,
		user: &str,
		password: &str,
	) -> Result<server::Auth, Self::Error> {
		self.calls.auth.fetch_add(1, Ordering::Relaxed);
		Ok(if user == "transfer" && password == SECRET {
			server::Auth::Accept
		} else {
			server::Auth::reject()
		})
	}

	async fn channel_open_session(
		&mut self,
		channel: Channel<server::Msg>,
		reply: server::ChannelOpenHandle,
		_session: &mut server::Session,
	) -> Result<(), Self::Error> {
		self.channel = Some(channel);
		reply.accept().await;
		Ok(())
	}

	async fn subsystem_request(
		&mut self,
		id: ChannelId,
		name: &str,
		session: &mut server::Session,
	) -> Result<(), Self::Error> {
		assert_eq!(name, "sftp");
		self.calls.subsystem.fetch_add(1, Ordering::Relaxed);
		if !self.subsystem {
			return session.channel_failure(id);
		}
		session.channel_success(id)?;
		let state = Files {
			calls: self.calls.clone(),
			listed: false,
			early_eof: self.early_eof,
		};
		sftp_server::run(self.channel.take().unwrap().into_stream(), state).await;
		Ok(())
	}

	async fn exec_request(
		&mut self,
		id: ChannelId,
		_data: &[u8],
		session: &mut server::Session,
	) -> Result<(), Self::Error> {
		self.calls.unsupported.fetch_add(1, Ordering::Relaxed);
		session.channel_failure(id)
	}
}

struct Files {
	calls: Arc<Calls>,
	listed: bool,
	early_eof: bool,
}

fn file_attrs() -> sftp::FileAttributes {
	sftp::FileAttributes {
		size: Some(CONTENT.len() as u64),
		permissions: Some(0o100600),
		mtime: Some(22),
		..sftp::FileAttributes::empty()
	}
}

impl sftp_server::Handler for Files {
	type Error = sftp::StatusCode;

	fn unimplemented(&self) -> Self::Error {
		self.calls.unsupported.fetch_add(1, Ordering::Relaxed);
		sftp::StatusCode::OpUnsupported
	}

	async fn lstat(&mut self, id: u32, path: sftp::SftpString) -> Result<sftp::Attrs, Self::Error> {
		assert_eq!(path.as_bytes(), NAME);
		Ok(sftp::Attrs {
			id,
			attrs: file_attrs(),
		})
	}

	async fn fstat(&mut self, id: u32, file: sftp::SftpHandle) -> Result<sftp::Attrs, Self::Error> {
		assert_eq!(file.as_bytes(), &[0, 255]);
		Ok(sftp::Attrs {
			id,
			attrs: file_attrs(),
		})
	}

	async fn opendir(
		&mut self,
		id: u32,
		path: sftp::SftpString,
	) -> Result<sftp::Handle, Self::Error> {
		assert_eq!(path.as_bytes(), b".");
		Ok(sftp::Handle {
			id,
			handle: sftp::SftpHandle::from("directory"),
		})
	}

	async fn readdir(&mut self, id: u32, dir: sftp::SftpHandle) -> Result<sftp::Name, Self::Error> {
		assert_eq!(dir.as_bytes(), b"directory");
		if std::mem::replace(&mut self.listed, true) {
			return Err(sftp::StatusCode::Eof);
		}
		Ok(sftp::Name {
			id,
			files: vec![
				sftp::File::dummy("."),
				sftp::File::dummy(".."),
				sftp::File::dummy(sftp::SftpString::from(NAME)),
			],
		})
	}

	async fn open(
		&mut self,
		id: u32,
		name: sftp::SftpString,
		flags: sftp::OpenFlags,
		_attrs: sftp::FileAttributes,
	) -> Result<sftp::Handle, Self::Error> {
		assert_eq!(name.as_bytes(), NAME);
		assert_eq!(flags.bits(), sftp::OpenFlags::READ.bits());
		Ok(sftp::Handle {
			id,
			handle: sftp::SftpHandle::from(&[0, 255]),
		})
	}

	async fn read(
		&mut self,
		id: u32,
		file: sftp::SftpHandle,
		offset: u64,
		len: u32,
	) -> Result<sftp::Data, Self::Error> {
		assert_eq!(file.as_bytes(), &[0, 255]);
		assert!(len > 0);
		let start = usize::try_from(offset).unwrap();
		if start >= CONTENT.len() || self.early_eof {
			return Err(sftp::StatusCode::Eof);
		}
		let end = (start + (len as usize).min(2)).min(CONTENT.len());
		Ok(sftp::Data {
			id,
			data: CONTENT[start..end].to_vec(),
		})
	}

	async fn close(
		&mut self,
		id: u32,
		_file: sftp::SftpHandle,
	) -> Result<sftp::Status, Self::Error> {
		self.calls.close.fetch_add(1, Ordering::Relaxed);
		Ok(sftp::Status {
			id,
			status_code: sftp::StatusCode::Ok,
			error_message: String::new(),
			language_tag: String::new(),
		})
	}
}

fn peer(subsystem: bool, early_eof: bool) -> (DuplexStream, HostKeyFingerprint, Arc<Calls>) {
	let (stream, pin, calls, _) = peer_with_handle(subsystem, early_eof);
	(stream, pin, calls)
}

fn peer_with_handle(
	subsystem: bool,
	early_eof: bool,
) -> (
	DuplexStream,
	HostKeyFingerprint,
	Arc<Calls>,
	oneshot::Receiver<server::Handle>,
) {
	let secret = Ed25519Keypair::from_seed(&[17; 32]);
	let key = PrivateKey::new(KeypairData::Ed25519(secret), "").unwrap();
	let pin = HostKeyFingerprint::from_sha256(
		key.public_key()
			.fingerprint(HashAlg::Sha256)
			.sha256()
			.unwrap(),
	);
	let (client, socket) = tokio::io::duplex(64 * 1024);
	let calls = Arc::new(Calls::default());
	let peer = Peer {
		channel: None,
		calls: calls.clone(),
		subsystem,
		early_eof,
	};
	let config = server::Config {
		keys: vec![key],
		..server::Config::default()
	};
	let (send_handle, receive_handle) = oneshot::channel();
	tokio::spawn(async move {
		if let Ok(session) = server::run_stream(Arc::new(config), socket, peer).await {
			let _ = send_handle.send(session.handle());
			let _ = session.await;
		}
	});
	(client, pin, calls, receive_handle)
}

fn authority(account: &str) -> SshAuthority {
	SshAuthority::new("sftp.example", NonZeroU16::new(22).unwrap(), account).unwrap()
}

#[tokio::test]
async fn raw_listing_and_short_reads_use_a_pinned_authenticated_connection() {
	let (stream, pin, calls) = peer(true, false);
	let target = authority("transfer");
	let mut session = connect(
		stream,
		&target,
		pin,
		|_, _| KnownHostStatus::Unknown,
		&target,
		|request| {
			assert_eq!(request.authority(), &target);
			assert_eq!(request.fingerprint(), pin);
			assert_eq!(request.source(), CredentialSource::SuppliedPassword);
			assert_eq!(request.interaction(), InteractionPolicy::Forbidden);
			assert_eq!(calls.auth.load(Ordering::Relaxed), 0);
			Password::new(SECRET.to_owned())
		},
	)
	.await
	.unwrap();

	assert_eq!(session.list(&[]).await.unwrap(), vec![NAME.to_vec()]);
	let path = [UnixComponent::new(NAME).unwrap()];
	let before = session.stat(&path).await.unwrap();
	assert_eq!(before.length, CONTENT.len() as u64);
	let mut bytes = [0; CONTENT.len()];
	assert_eq!(session.read_file(&path, &mut bytes).await.unwrap(), before);
	assert_eq!(&bytes, CONTENT);
	assert_eq!(calls.auth.load(Ordering::Relaxed), 1);
	assert_eq!(calls.subsystem.load(Ordering::Relaxed), 1);
	assert_eq!(calls.close.load(Ordering::Relaxed), 2);
	assert_eq!(calls.unsupported.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_mismatched_pin_or_revocation_never_requests_or_sends_a_credential() {
	let target = authority("transfer");
	for (known, expected) in [
		(KnownHostStatus::Unknown, HostKeyRefusal::PinMismatch),
		(KnownHostStatus::Revoked, HostKeyRefusal::Revoked),
	] {
		let (stream, pin, calls) = peer(true, false);
		let selected = if known == KnownHostStatus::Unknown {
			HostKeyFingerprint::from_sha256([0; 32])
		} else {
			pin
		};
		let result = connect(
			stream,
			&target,
			selected,
			move |_, _| known,
			&target,
			|_| panic!("broker called before trust"),
		);
		assert!(matches!(result.await, Err(Error::HostKey(refusal)) if refusal == expected));
		assert_eq!(calls.auth.load(Ordering::Relaxed), 0);
		assert_eq!(calls.subsystem.load(Ordering::Relaxed), 0);
	}
}

#[tokio::test]
async fn a_credential_for_another_account_cannot_be_acquired_or_sent() {
	let (stream, pin, calls) = peer(true, false);
	let target = authority("transfer");
	let other = authority("unrelated");
	let result = connect(
		stream,
		&target,
		pin,
		|_, _| KnownHostStatus::Unknown,
		&other,
		|_| panic!("broker called for an unrelated account"),
	)
	.await;
	assert!(matches!(
		result,
		Err(Error::Credential(CredentialRefusal::AuthorityMismatch))
	));
	assert_eq!(calls.auth.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_refused_sftp_subsystem_never_falls_back_to_a_shell() {
	let (stream, pin, calls) = peer(false, false);
	let target = authority("transfer");
	let result = connect(
		stream,
		&target,
		pin,
		|_, _| KnownHostStatus::Unknown,
		&target,
		|_| Password::new(SECRET.to_owned()),
	)
	.await;

	assert!(matches!(result, Err(Error::Subsystem)));
	assert_eq!(calls.auth.load(Ordering::Relaxed), 1);
	assert_eq!(calls.subsystem.load(Ordering::Relaxed), 1);
	assert_eq!(calls.unsupported.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn early_eof_refuses_incomplete_reads_and_fences_the_session() {
	let (stream, pin, _) = peer(true, true);
	let target = authority("transfer");
	let mut session = connect(
		stream,
		&target,
		pin,
		|_, _| KnownHostStatus::Unknown,
		&target,
		|_| Password::new(SECRET.to_owned()),
	)
	.await
	.unwrap();
	let path = [UnixComponent::new(NAME).unwrap()];
	let mut bytes = [0; CONTENT.len()];
	assert!(matches!(
		session.read_file(&path, &mut bytes).await,
		Err(Error::Changed)
	));
	assert!(matches!(session.stat(&path).await, Err(Error::Closed)));
}

#[tokio::test]
async fn a_peer_initiated_channel_is_refused_and_the_connection_is_fenced() {
	let (stream, pin, _, handle) = peer_with_handle(true, false);
	let target = authority("transfer");
	let mut session = connect(
		stream,
		&target,
		pin,
		|_, _| KnownHostStatus::Unknown,
		&target,
		|_| Password::new(SECRET.to_owned()),
	)
	.await
	.unwrap();
	let handle = handle.await.unwrap();
	assert!(handle.channel_open_session().await.is_err());
	let path = [UnixComponent::new(NAME).unwrap()];
	assert!(matches!(
		session.stat(&path).await,
		Err(Error::UnsolicitedChannel)
	));
	assert!(matches!(session.stat(&path).await, Err(Error::Closed)));
}
